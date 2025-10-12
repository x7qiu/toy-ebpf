package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
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
)

// --- Helper Functions ---

// Helper to convert a uint32 IP address to a net.IP byte slice (Big Endian).
func uint32ToBytes(u uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, u)
	return b
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
	// Create a canonical flow key for aggregation (to handle both directions).
	// This ensures that A->B and B->A packets map to the same statistics entry.
	var key FlowKey
	
	// Canonical flow check: compare IP addresses first, then ports if IPs are equal.
	// Note: Comparing ports is only valid for protocols that use them (TCP/UDP).
	isCanonical := false
	if info.Saddr < info.Daddr {
		isCanonical = true
	} else if info.Saddr == info.Daddr {
		// Use transport ports as tie-breaker for the canonical flow key
		if info.Sport < info.Dport {
			isCanonical = true
		}
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

	stats.TotalPackets += info.PktCount
	stats.TotalBytes += uint64(info.ByteCount)
	stats.LastSeen = time.Now().Unix()
}

// printReport periodically prints the aggregated flow statistics.
func printReport() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		mu.Lock()
		if len(flows) == 0 {
			mu.Unlock()
			continue
		}

		// Clear screen and print header (simulating a screen refresh like 'top' or 'iftop')
		fmt.Print("\033[H\033[2J") // ANSI sequence to clear screen and home cursor
		fmt.Println("--- Network Flow Monitor (Aggregated, Last 5s Window) ---")
		fmt.Println("Flows tracked:", len(flows))
		fmt.Println(
			"--------------------------------------------------------------------------------------------------------------\n" +
			"| PROTOCOL | A IP:PORT           | B IP:PORT           | TOTAL PKTS | TOTAL BYTES | LAST SEEN (s ago) |\n" +
			"--------------------------------------------------------------------------------------------------------------")

		currentTime := time.Now().Unix()

		// Prepare flows to reset and print
		flowsToKeep := make(map[FlowKey]*FlowStats)

		for key, stats := range flows {
			// Calculate elapsed time
			elapsed := currentTime - stats.LastSeen

			// Format A and B IP/Port (always print flow based on canonical A->B)
			srcIP := net.IP(uint32ToBytes(key.Saddr)).String()
			dstIP := net.IP(uint32ToBytes(key.Daddr)).String()
			
			// Format A:B ports (use canonical A:B, which may be S:D or D:S from the original packet)
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

			// Simple cleanup: If a flow hasn't been seen in 3 reporting intervals (15 seconds), discard it.
			if elapsed < 15 {
				flowsToKeep[key] = stats
			}
			
			// Reset counters for the next 5-second window
			stats.TotalPackets = 0
			stats.TotalBytes = 0
		}
		
		flows = flowsToKeep
		mu.Unlock()
	}
}


func main() {
	// Step 1: Set up signal handler for graceful exit.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Step 2: Load the eBPF program (NetMonitor).
	objs := ebpfObjects{}
	if err := loadEbpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading eBPF objects: %v", err)
	}
	defer objs.Close()

	// Step 3: Determine the interface index (ifindex) for attachment.
	ifname := "enp0s1" // *** IMPORTANT: Change this to your network interface name (e.g., eth0, ens33, enp0s3) ***
	
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("could not find interface %s: %v", ifname, err)
	}
	ifindex := iface.Index
	
	// Step 4: Attach the eBPF program to a network interface using its index.
	progLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.NetMonitor, // Program name defined in capture.c SEC("xdp")
		Interface: ifindex,
		Flags:     0,
	})
	if err != nil {
		log.Fatalf("attaching XDP program to %s (index %d): %v", ifname, ifindex, err)
	}
	defer progLink.Close()
	log.Printf("eBPF Network Monitor attached to %s (index %d)", ifname, ifindex)

	// Step 5: Create a ring buffer reader to receive data from the kernel.
	rd, err := ringbuf.NewReader(objs.Packets) // 'Packets' map name is defined in capture.c
	if err != nil {
		log.Fatalf("creating ring buffer reader: %v", err)
	}
	defer rd.Close()

	// Step 6: Start the reporting goroutine immediately.
	go printReport()
	
	// Step 7: Start goroutine to read from the ring buffer and aggregate data.
	go func() {
		var info packet_info
		for {
			record, err := rd.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return
				}
				log.Printf("reading from ring buffer: %v", err)
				continue
			}
			
			// Decode the raw bytes from the kernel into our Go struct.
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &info); err != nil {
				log.Printf("decoding packet info: %v", err)
				continue
			}
			
			// Instead of printing, aggregate the received packet data.
			aggregatePacket(&info)
		}
	}()

	// Step 8: Wait for a signal to exit.
	<-stopper
	log.Println("Exiting network monitor.")
}
