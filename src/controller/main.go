package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

//go:embed bpf/xdp_main.bpf.o
var bpfObject []byte

func metricsHandler(reader statsProvider) http.Handler {
	registry := prometheus.NewRegistry()
	registry.MustRegister(NewByteGuardCollector(reader))
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	return mux
}

func main() {
	if err := run(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

func run() error {
	ifaceName := flag.String("interface", "", "Network interface to attach XDP to")
	mode := flag.String("mode", "native", "XDP mode: native or generic")
	metricsAddress := flag.String("metrics-address", ":9090", "HTTP metrics listen address (in the controller's network namespace)")
	flag.Parse()
	if *ifaceName == "" {
		return fmt.Errorf("missing required argument: --interface")
	}
	var xdpFlags link.XDPAttachFlags
	switch *mode {
	case "native":
		xdpFlags = link.XDPDriverMode
	case "generic":
		xdpFlags = link.XDPGenericMode
	default:
		return fmt.Errorf("invalid XDP mode %q: use native or generic", *mode)
	}
	iface, err := net.InterfaceByName(*ifaceName)
	if err != nil {
		return fmt.Errorf("find interface %q: %w", *ifaceName, err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Fail on a port collision before loading or attaching anything.
	listener, err := net.Listen("tcp", *metricsAddress)
	if err != nil {
		return fmt.Errorf("listen for metrics on %s: %w", *metricsAddress, err)
	}
	defer listener.Close()
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove BPF memlock limit: %w", err)
	}
	log.Printf("Embedded BPF object: %d bytes, sha256=%x", len(bpfObject), sha256.Sum256(bpfObject))
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfObject))
	if err != nil {
		return fmt.Errorf("parse embedded BPF object: %w", err)
	}
	objects, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("load BPF collection: %w", err)
	}
	defer objects.Close()
	statMap, ok := objects.Maps["stat_map"]
	if !ok {
		return fmt.Errorf("stat_map not found in BPF object")
	}
	statsReader, err := NewStatsReader(statMap)
	if err != nil {
		return fmt.Errorf("initialize stats reader: %w", err)
	}
	stats, err := statsReader.Read()
	if err != nil {
		return fmt.Errorf("read initial BPF statistics: %w", err)
	}
	log.Printf("Initial stats: %+v", stats)
	prog, ok := objects.Programs["xdp_main"]
	if !ok {
		return fmt.Errorf("program xdp_main not found in BPF object")
	}
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program: prog, Interface: iface.Index, Flags: xdpFlags,
	})
	if err != nil {
		return fmt.Errorf("attach XDP in %s mode to %s: %w", *mode, iface.Name, err)
	}
	defer func() {
		if err := xdpLink.Close(); err != nil {
			log.Printf("detach XDP: %v", err)
		}
	}()
	log.Printf("ByteGuard attached to %s (ifindex %d, mode %s)", iface.Name, iface.Index, *mode)
	server := &http.Server{
		Handler: metricsHandler(statsReader), ReadHeaderTimeout: 5 * time.Second,
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Printf("shutdown metrics server: %v", err)
			server.Close()
		}
	}()
	serverErrors := make(chan error, 1)
	go func() { serverErrors <- server.Serve(listener) }()
	log.Printf("Metrics listening on %s; Ctrl+C detaches XDP", listener.Addr())
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			stats, err := statsReader.Read()
			if err != nil {
				log.Printf("read BPF statistics: %v", err)
				continue
			}
			log.Printf("DNS queries: %d | XDP admitted: %d | Dropped: %d | Source limit: %d | Global limit: %d",
				stats.DNSQueries, stats.DNSPass, stats.PacketDrops, stats.DropSourceLimit, stats.DropGlobalLimit)
		case err := <-serverErrors:
			if !errors.Is(err, http.ErrServerClosed) {
				return fmt.Errorf("metrics server stopped: %w", err)
			}
			return nil
		case <-ctx.Done():
			log.Print("Stopping ByteGuard and detaching XDP")
			return nil
		}
	}
}
