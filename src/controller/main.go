package main

import (
	"bytes"
	_ "embed"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
	"net/http"

"github.com/prometheus/client_golang/prometheus"
"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:embed bpf/xdp_main.bpf.o
var bpfObject []byte

func main() {
	ifaceName := flag.String("interface", "", "Network interface to attach XDP to")
	// objectPath := flag.String("object", "../../build/xdp_main.bpf.o", "Path to BPF ELF object")
	mode := flag.String("mode", "native", "XDP mode: native or generic")
	flag.Parse()

	if *ifaceName == "" {
		log.Fatal("missing required argument: --interface")
	}

	// Resolve the interface name to its system interface index.
	iface, err := net.InterfaceByName(*ifaceName)
	if err != nil {
		log.Fatalf("failed to find interface %q: %v", *ifaceName, err)
	}

	// Read the compiled BPF ELF object.
	fmt.Printf("Embedded BPF object size: %d bytes\n", len(bpfObject))
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfObject))
	if err != nil {
		log.Fatalf("failed to load BPF object: %v", err)
	}

	// Load its programs and maps into the kernel.
	objects, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("failed to load BPF collection: %v", err)
	}
	defer objects.Close()
	statMap, ok := objects.Maps["stat_map"]
	if !ok {
		log.Fatal("stat_map not found in BPF object")
	}

	statsReader, err := NewStatsReader(statMap)
	if err != nil {
		log.Fatalf("failed to initialize stats reader: %v", err)
	}

	fmt.Println("ByteGuard statistics reader initialized.")
	registry := prometheus.NewRegistry()

collector := NewByteGuardCollector(statsReader)
registry.MustRegister(collector)

http.Handle("/metrics", promhttp.HandlerFor(
	registry,
	promhttp.HandlerOpts{},
))

go func() {
	log.Println("Metrics server listening on :9090")
	if err := http.ListenAndServe(":9090", nil); err != nil {
		log.Printf("metrics server stopped: %v", err)
	}
}()

	// Find the XDP program by its ELF program name.
	prog, ok := objects.Programs["xdp_main"]
	if !ok {
		log.Fatal("program xdp_main not found in BPF object")
	}

	// Attach in generic mode, useful for our initial veth testing.

	var xdpFlags link.XDPAttachFlags

	switch *mode {
	case "native":
		xdpFlags = link.XDPDriverMode
	case "generic":
		xdpFlags = link.XDPGenericMode
	default:
		log.Fatalf("invalid XDP mode %q: use native or generic", *mode)
	}

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
		Flags:     xdpFlags,
	})
	if err != nil {
		log.Fatalf("failed to attach XDP in %s mode to %s: %v",
			*mode, iface.Name, err)
	}
	defer xdpLink.Close()
	fmt.Printf("ByteGuard attached to %s (ifindex %d)\n", iface.Name, iface.Index)
	fmt.Println("Press Ctrl+C to stop.")
	stats, err := statsReader.Read()
	if err != nil {
		log.Fatalf("failed to read BPF statistics: %v", err)
	}

	fmt.Printf("Initial stats: %+v\n", stats)

	// Keep the program attached until termination.
	fmt.Println("Press Ctrl+C to stop.")

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			stats, err := statsReader.Read()
			if err != nil {
				log.Printf("failed to read statistics: %v", err)
				continue
			}

			fmt.Printf(
				"DNS queries: %d | Passed: %d | Dropped: %d | Source limit: %d | Global limit: %d\n",
				stats.DNSQueries,
				stats.DNSPass,
				stats.PacketDrops,
				stats.DropSourceLimit,
				stats.DropGlobalLimit,
			)

		case <-stop:
			fmt.Println("\nStopping ByteGuard...")
			return
		}
	}

	fmt.Println("\nStopping ByteGuard...")
}
