package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

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

	// Keep the program attached until termination.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	fmt.Println("\nStopping ByteGuard...")
}
