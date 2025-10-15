package main

import (
	"bytes"
	"errors"
	"encoding/binary"
	"flag"
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


var (
	flows = make(map[FlowKey]*FlowStats)
	mu    sync.Mutex // Mutex to protect map access across goroutines

	// Set of ports considered 'server' or 'well-known'
	wellKnownPorts map[uint16]bool 
	
	ifaceName = flag.String("iface", "eth0", "Network interface name (e.g., enp0s1, eth0)")
	durationStr = flag.String("duration", "1h", "Reporting window duration (e.g., 5s, 30m, 1h)")
	portsFile = flag.String("ports-file", "", "Path to a file listing well-known server ports (one per line)")
)


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


func main() {
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