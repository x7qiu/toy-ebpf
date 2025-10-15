package main

import (
		"encoding/binary"
		"strings"
		"fmt"
		"os"
		"strconv"
		"log"
		"time"
		"net"

		"github.com/google/gopacket/layers"
)

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