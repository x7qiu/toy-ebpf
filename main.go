package main

import (
	"bytes"
	"errors"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"sync" 
	"time" 

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/google/gopacket/layers"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall" ebpf ebpf/capture.bpf.c

// --- Data Structure Definitions (Must match capture.bpf.c) ---

// User-space data structure for per-packet flow monitoring.
// The tag 'align:"1"' is crucial here. It forces the Go struct to use
// single-byte packing, matching the __attribute__((packed)) usually applied
// to C structs passed via eBPF, fixing the reading of PktCount and ByteCount.
type packet_info struct {
	DestMac    [6]byte `align:"1"`
	SrcMac     [6]byte `align:"1"`
	Saddr      uint32  `align:"1"`
	Daddr      uint32  `align:"1"`
	Sport      uint16  `align:"1"`
	Dport      uint16  `align:"1"`
	Protocol   uint8   `align:"1"`
	PktCount   uint64  `align:"1"` // Was reading garbage due to misalignment
	ByteCount  uint32  `align:"1"` // Was reading 0 due to misalignment
}

// FlowKey represents the 5-tuple for bidirectional flow aggregation.
type FlowKey struct {
	Saddr    uint32
	Daddr    uint32
	Sport    uint16
	Dport    uint16
	Protocol uint8
}

// FlowStats holds aggregated metrics for a single flow.
type FlowStats struct {
	TotalPackets uint64
	TotalBytes   uint64
	LastSeen     int64
}

// --- Global Aggregation State ---

var (
	flows = make(map[FlowKey]*FlowStats)
	mu    sync.Mutex // Mutex to protect map access across goroutines

	// Set of ports considered 'server' or 'well-known'
	wellKnownPorts map[uint16]bool 
	
	ifaceName = flag.String("iface", "eth0", "Network interface name (e.g., enp0s1, eth0)")
	durationStr = flag.String("duration", "1h", "Reporting window duration (e.g., 5s, 30m, 1h)")
	portsFile = flag.String("ports-file", "", "Path to a file listing well-known server ports (one per line)")
)

// --- Helper Functions ---

// Helper to convert a uint32 IP address to a net.IP byte slice (Big Endian).
func uint32ToBytes(u uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, u)
	return b
}

// loadWellKnownPorts reads the list of well-known server ports from a file.
func loadWellKnownPorts(filepath string) map[uint16]bool {
	ports := make(map[uint16]bool)
	if filepath == "" {
		return ports
	}

	content, err := os.ReadFile(filepath)
	if err != nil {
		log.Printf("Warning: Could not read ports file %s: %v. Using default ports.", filepath, err)
		return ports
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		portInt, err := strconv.ParseUint(line, 10, 16)
		if err != nil {
			log.Printf("Warning: Invalid port '%s' in file. Skipping.", line)
			continue
		}
		ports[uint16(portInt)] = true
	}
	
	// Always include standard well-known ports if file is provided or not.
	ports[21] = true // FTP
	ports[22] = true // SSH
	ports[23] = true // Telnet
	ports[25] = true // SMTP
	ports[53] = true // DNS (TCP/UDP)
	ports[80] = true // HTTP
	ports[443] = true // HTTPS
	ports[502] = true // Modbus TCP
	
	log.Printf("Loaded %d well-known ports for flow direction inference.", len(ports))
	return ports
}

// Map IP protocol numbers to human-readable strings.
var protocolNames = map[uint8]string{
	uint8(layers.IPProtocolICMPv4): "ICMP",
	uint8(layers.IPProtocolTCP):   "TCP",
	uint8(layers.IPProtocolUDP):   "UDP",
	uint8(layers.IPProtocolIPv6):  "IPv6",
	uint8(layers.IPProtocolIPIP):  "IPIP",
}

func getProtocolName(p uint8) string {
	if name, ok := protocolNames[p]; ok {
		return name
	}
	return fmt.Sprintf("IP:%d", p)
}

// --- Flow Aggregation and Reporting Logic ---

// aggregatePacket updates the flow statistics based on a new packet.
func aggregatePacket(info *packet_info) {
	var key FlowKey
	
	// Canonical flow determination: A is the client, B is the server.
	
	// 1. Check well-known ports (for TCP/UDP only)
	isWellKnown := false
	if info.Protocol == uint8(layers.IPProtocolTCP) || info.Protocol == uint8(layers.IPProtocolUDP) {
		isWellKnown = wellKnownPorts[info.Sport] || wellKnownPorts[info.Dport]
	}
	
	isCanonical := false
	
	if isWellKnown {
		// If both ports are well-known, revert to IP ordering to avoid ambiguity.
		if wellKnownPorts[info.Sport] && wellKnownPorts[info.Dport] {
			isCanonical = info.Saddr < info.Daddr || (info.Saddr == info.Daddr && info.Sport < info.Dport)
		} else if wellKnownPorts[info.Dport] {
			// Traffic is CLIENT(Sport) -> SERVER(Dport). This is canonical.
			isCanonical = true
		} else {
			// Traffic is SERVER(Sport) -> CLIENT(Dport). This is REVERSE canonical.
			isCanonical = false
		}
	} else {
		// 2. If no well-known ports, use IP address ordering as the tie-breaker
		isCanonical = info.Saddr < info.Daddr || (info.Saddr == info.Daddr && info.Sport < info.Dport)
	}


	if isCanonical {
		// Direction 1: A->B
		key = FlowKey{
			Saddr:    info.Saddr,
			Daddr:    info.Daddr,
			Sport:    info.Sport,
			Dport:    info.Dport,
			Protocol: info.Protocol,
		}
	} else {
		// Direction 2: B->A (reverse the flow to map to Direction 1's key)
		key = FlowKey{
			Saddr:    info.Daddr,
			Daddr:    info.Saddr,
			Sport:    info.Dport,
			Dport:    info.Sport,
			Protocol: info.Protocol,
		}
	}

	mu.Lock()
	defer mu.Unlock()

	stats, exists := flows[key]
	if !exists {
		stats = &FlowStats{
			TotalPackets: 0,
			TotalBytes:   0,
		}
		flows[key] = stats
	}

	// The C code currently sends PktCount=1, ByteCount=pkt_len.
	// We aggregate them here.
	stats.TotalPackets += info.PktCount
	stats.TotalBytes += uint64(info.ByteCount)
	stats.LastSeen = time.Now().Unix()
}

// printReport periodically prints the aggregated flow statistics.
func printReport(reportDuration time.Duration) {
	// Use the command-line duration for the ticker interval
	ticker := time.NewTicker(reportDuration)
	defer ticker.Stop()

	// Simple flow cleanup timeout (3x the report duration)
	cleanupTimeout := int64(reportDuration.Seconds()) * 3

	for range ticker.C {
		mu.Lock()
		if len(flows) == 0 {
			mu.Unlock()
			continue
		}

		// Clear screen and print header
		fmt.Print("\033[H\033[2J") 
		fmt.Println("--- Network Flow Monitor (Aggregated, Reporting Window:", reportDuration.String(), ") ---")
		fmt.Println("Flows tracked:", len(flows))
		fmt.Println(
			"--------------------------------------------------------------------------------------------------------------\n" +
			"| PROTOCOL | A IP:PORT           | B IP:PORT           | TOTAL PKTS | TOTAL BYTES | LAST SEEN (s ago) |\n" +
			"--------------------------------------------------------------------------------------------------------------")

		currentTime := time.Now().Unix()

		// Prepare flows to reset and print
		flowsToKeep := make(map[FlowKey]*FlowStats)

		for key, stats := range flows {
			elapsed := currentTime - stats.LastSeen

			// Format A and B IP/Port (A is the client side of the canonical flow)
			srcIP := net.IP(uint32ToBytes(key.Saddr)).String()
			dstIP := net.IP(uint32ToBytes(key.Daddr)).String()
			
			srcPort := ""
			dstPort := ""
			if key.Sport != 0 || key.Dport != 0 {
				srcPort = fmt.Sprintf(":%d", key.Sport)
				dstPort = fmt.Sprintf(":%d", key.Dport)
			}
			
			// Print the aggregated row
			fmt.Printf("| %-8s | %-20s| %-20s| %-10d | %-11d | %-17d |\n",
				getProtocolName(key.Protocol),
				srcIP + srcPort,
				dstIP + dstPort,
				stats.TotalPackets,
				stats.TotalBytes,
				elapsed,
			)

			// Cleanup: If flow hasn't been seen in the cleanup timeout, discard it.
			if elapsed < cleanupTimeout {
				flowsToKeep[key] = stats
			}
			
			// Reset counters for the next reporting window
			stats.TotalPackets = 0
			stats.TotalBytes = 0
		}
		
		flows = flowsToKeep
		mu.Unlock()
	}
}


func main() {
	// Parse command line arguments
	flag.Parse()
	
	// Parse duration string into time.Duration
	reportDuration, err := time.ParseDuration(*durationStr)
	if err != nil {
		log.Fatalf("Invalid duration format: %v. Use formats like 5s, 1m, 1h.", err)
	}

	// Load well-known ports based on the flag
	wellKnownPorts = loadWellKnownPorts(*portsFile)

	// Step 1: Set up signal handler for graceful exit.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Step 2: Load the eBPF program (NetMonitor).
	// We rely on 'go generate' having been run successfully.
	objs := ebpfObjects{}
	if err := loadEbpfObjects(&objs, nil); err != nil {
		log.Fatalf("Loading eBPF objects failed. Did you run 'go generate ./...'? Error: %v", err)
	}
	defer objs.Close()

	// Step 3: Determine the interface index (ifindex) for attachment.
	iface, err := net.InterfaceByName(*ifaceName)
	if err != nil {
		log.Fatalf("Could not find network interface '%s': %v", *ifaceName, err)
	}
	ifindex := iface.Index
	
	// Step 4: Attach the eBPF program to a network interface using its index.
	progLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.NetMonitor, // Program name defined in capture.c SEC("xdp")
		Interface: ifindex,
		Flags:     0,
	})
	if err != nil {
		log.Fatalf("Attaching XDP program to %s (index %d) failed: %v", *ifaceName, ifindex, err)
	}
	defer progLink.Close()
	log.Printf("eBPF Network Monitor attached to %s (index %d). Reporting every %s.", *ifaceName, ifindex, reportDuration.String())

	// Step 5: Create a ring buffer reader to receive data from the kernel.
	rd, err := ringbuf.NewReader(objs.Packets) 
	if err != nil {
		log.Fatalf("Creating ring buffer reader failed: %v", err)
	}
	defer rd.Close()

	// Step 6: Start the reporting goroutine.
	// Pass the dynamically parsed duration.
	go printReport(reportDuration)
	
	// Step 7: Start goroutine to read from the ring buffer and aggregate data.
	go func() {
		var info packet_info
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) { // Use errors.Is for comparison
					return
				}
				log.Printf("reading from ring buffer: %v", err)
				continue
			}
			
			// Decode the raw bytes from the kernel into our Go struct.
			// The use of align:"1" tag in the struct helps ensure correct decoding here.
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &info); err != nil {
				log.Printf("decoding packet info: %v", err)
				continue
			}
			
			// Aggregate the received packet data.
			aggregatePacket(&info)
		}
	}()

	// Step 8: Wait for a signal to exit.
	<-stopper
	log.Println("Exiting network monitor.")
}