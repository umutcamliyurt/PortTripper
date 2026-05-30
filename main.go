package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)


type Config struct {
	PortFile            string
	StartPort           int
	EndPort             int
	Verbose             bool
	JSONLog             bool
	HoldSeconds         int
	MaxConnsTotal       int64
	RateLimitPerIP      int
	EnableUDP           bool
	MetricsAddr         string
}

func defaultConfig() Config {
	return Config{
		PortFile:       "whitelist.txt",
		StartPort:      1024,
		EndPort:        65000,
		Verbose:        false,
		JSONLog:        false,
		HoldSeconds:    2,
		MaxConnsTotal:  10_000,
		RateLimitPerIP: 5,
		EnableUDP:      true,
		MetricsAddr:    "",
	}
}


type Metrics struct {
	TotalAccepted  atomic.Int64
	TotalRejected  atomic.Int64
	ActiveConns    atomic.Int64
	SkippedPorts   atomic.Int64
	BoundPorts     atomic.Int64
	FailedBinds    atomic.Int64
}

var metrics Metrics


const maxRateLimiterBuckets = 100_000

type ipBucket struct {
	tokens    int
	lastRefil time.Time
}

type RateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*ipBucket
	limit   int
}

func newRateLimiter(limit int) *RateLimiter {
	if limit < 1 {
		limit = 1
	}
	rl := &RateLimiter{
		buckets: make(map[string]*ipBucket),
		limit:   limit,
	}
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			rl.evict()
		}
	}()
	return rl
}

func normalizeIP(ip string) string {
	if i := strings.IndexByte(ip, '%'); i != -1 {
		return ip[:i]
	}
	return ip
}

func (rl *RateLimiter) Allow(ip string) bool {
	ip = normalizeIP(ip)
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	b, ok := rl.buckets[ip]
	if !ok {
		if len(rl.buckets) >= maxRateLimiterBuckets {
			return false
		}
		b = &ipBucket{tokens: rl.limit, lastRefil: now}
		rl.buckets[ip] = b
	}
	elapsed := now.Sub(b.lastRefil).Seconds()
	if elapsed < 0 {
		elapsed = 0
		b.lastRefil = now
	}
	refill := int(elapsed * float64(rl.limit))
	if refill > 0 {
		b.tokens += refill
		if b.tokens > rl.limit {
			b.tokens = rl.limit
		}
		b.lastRefil = now
	}
	if b.tokens <= 0 {
		return false
	}
	b.tokens--
	return true
}

func (rl *RateLimiter) evict() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	cutoff := time.Now().Add(-30 * time.Second)
	for ip, b := range rl.buckets {
		if b.lastRefil.Before(cutoff) {
			delete(rl.buckets, ip)
		}
	}
}


type Logger struct {
	verbose  bool
	jsonMode bool
	mu       sync.Mutex
}

func (l *Logger) log(level, msg string, fields map[string]any) {
	if !l.verbose && level == "DEBUG" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.jsonMode {
		entry := map[string]any{
			"ts":    time.Now().UTC().Format(time.RFC3339Nano),
			"level": level,
			"msg":   msg,
		}
		for k, v := range fields {
			if s, ok := v.(string); ok {
				entry[k] = sanitizeLogValue(s)
			} else {
				entry[k] = v
			}
		}
		b, _ := json.Marshal(entry)
		fmt.Println(string(b))
	} else {
		parts := []string{
			time.Now().UTC().Format("2006-01-02T15:04:05Z"),
			"[" + level + "]",
			msg,
		}
		for k, v := range fields {
			var raw string
			if s, ok := v.(string); ok {
				raw = s
			} else {
				raw = fmt.Sprintf("%v", v)
			}
			parts = append(parts, fmt.Sprintf("%s=%s", k, sanitizeLogValue(raw)))
		}
		log.Println(strings.Join(parts, " "))
	}
}

func sanitizeLogValue(s string) string {
	const maxLogValueLen = 256
	var b strings.Builder
	b.Grow(len(s))
	n := 0
	for _, r := range s {
		if r >= 0x20 && r != 0x7f {
			b.WriteRune(r)
			n++
			if n >= maxLogValueLen {
				b.WriteString("...")
				break
			}
		}
	}
	return b.String()
}

func (l *Logger) Info(msg string, fields map[string]any)  { l.log("INFO", msg, fields) }
func (l *Logger) Warn(msg string, fields map[string]any)  { l.log("WARN", msg, fields) }
func (l *Logger) Debug(msg string, fields map[string]any) { l.log("DEBUG", msg, fields) }
func (l *Logger) Error(msg string, fields map[string]any) { l.log("ERROR", msg, fields) }


func discoverBoundPorts(start, end int) []int {
	var found []int
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 512)

	for port := start; port <= end; port++ {
		wg.Add(1)
		p := port
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			addr := fmt.Sprintf(":%d", p)
			taken := false

			if ln, err := net.Listen("tcp", addr); err != nil {
				taken = true
			} else {
				ln.Close()
			}

			if !taken {
				if c, err := net.ListenPacket("udp", addr); err != nil {
					taken = true
				} else {
					c.Close()
				}
			}

			if taken {
				mu.Lock()
				found = append(found, p)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	sort.Ints(found)
	return found
}

func ensureWhitelist(path string, start, end int, logger *Logger) (created bool, err error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		if os.IsExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("creating whitelist %q: %w", path, err)
	}
	defer f.Close()

	logger.Info("first run: scanning for already-bound ports",
		map[string]any{"range": fmt.Sprintf("%d-%d", start, end)})

	ports := discoverBoundPorts(start, end)

	w := bufio.NewWriter(f)
	fmt.Fprintln(w, "# PortTripper – port whitelist (auto-generated on first run)")
	fmt.Fprintln(w, "# Ports below were already bound by other processes at startup.")
	fmt.Fprintln(w, "# Edit freely: lines starting with '#' and blank lines are ignored.")
	fmt.Fprintln(w)
	for _, p := range ports {
		fmt.Fprintln(w, p)
	}
	if err := w.Flush(); err != nil {
		return false, fmt.Errorf("writing whitelist %q: %w", path, err)
	}
	return true, nil
}

func loadWhitelist(path string) (map[int]struct{}, error) {
	ports := make(map[int]struct{})
	f, err := os.Open(path)
	if err != nil {
		return ports, err
	}
	defer f.Close()

	const maxLineBytes = 1 << 20
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), maxLineBytes)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p, err := strconv.Atoi(line)
		if err != nil || p < 1 || p > 65535 {
			continue
		}
		ports[p] = struct{}{}
	}
	return ports, scanner.Err()
}


func startTCPListener(
	ctx context.Context,
	port int,
	cfg Config,
	rl *RateLimiter,
	logger *Logger,
) {
	addr := fmt.Sprintf(":%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		metrics.FailedBinds.Add(1)
		logger.Debug("TCP bind failed", map[string]any{"port": port, "err": err})
		return
	}
	metrics.BoundPorts.Add(1)
	logger.Debug("TCP listening", map[string]any{"port": port})

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	go func() {
		errCount := 0
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					errCount++
					if errCount > 8 {
						time.Sleep(50 * time.Millisecond)
					}
					logger.Debug("accept error", map[string]any{"port": port, "err": err})
					continue
				}
			}
			errCount = 0

			srcIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
			if !rl.Allow(srcIP) {
				metrics.TotalRejected.Add(1)
				logger.Warn("rate limit exceeded", map[string]any{"src": srcIP, "port": port})
				conn.Close()
				continue
			}

			for {
				cur := metrics.ActiveConns.Load()
				if cur >= cfg.MaxConnsTotal {
					metrics.TotalRejected.Add(1)
					conn.Close()
					goto nextConn
				}
				if metrics.ActiveConns.CompareAndSwap(cur, cur+1) {
					break
				}
			}

			metrics.TotalAccepted.Add(1)
			logger.Info("connection", map[string]any{"src": srcIP, "port": port, "proto": "tcp"})

			go func(c net.Conn) {
				defer func() {
					c.Close()
					metrics.ActiveConns.Add(-1)
				}()
				select {
				case <-time.After(time.Duration(cfg.HoldSeconds) * time.Second):
				case <-ctx.Done():
				}
			}(conn)
		nextConn:
		}
	}()
}


func startUDPListener(
	ctx context.Context,
	port int,
	cfg Config,
	rl *RateLimiter,
	logger *Logger,
) {
	addr := fmt.Sprintf(":%d", port)
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		metrics.FailedBinds.Add(1)
		logger.Debug("UDP bind failed", map[string]any{"port": port, "err": err})
		return
	}
	metrics.BoundPorts.Add(1)

	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	go func() {
		buf := make([]byte, 4096)
		errCount := 0
		for {
			_, src, err := conn.ReadFrom(buf)
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					errCount++
					if errCount > 8 {
						time.Sleep(50 * time.Millisecond)
					}
					continue
				}
			}
			errCount = 0
			srcIP, _, _ := net.SplitHostPort(src.String())
			if !rl.Allow(srcIP) {
				metrics.TotalRejected.Add(1)
				continue
			}
			metrics.TotalAccepted.Add(1)
			logger.Debug("connection", map[string]any{"src": srcIP, "port": port, "proto": "udp"})
		}
	}()
}


func startMetricsServer(addr string, logger *Logger) {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "# HELP PortTripper_connections_total Total accepted connections\n")
		fmt.Fprintf(w, "# TYPE PortTripper_connections_total counter\n")
		fmt.Fprintf(w, "PortTripper_connections_total %d\n", metrics.TotalAccepted.Load())

		fmt.Fprintf(w, "# HELP PortTripper_connections_rejected_total Total rejected connections\n")
		fmt.Fprintf(w, "# TYPE PortTripper_connections_rejected_total counter\n")
		fmt.Fprintf(w, "PortTripper_connections_rejected_total %d\n", metrics.TotalRejected.Load())

		fmt.Fprintf(w, "# HELP PortTripper_connections_active Current active connections\n")
		fmt.Fprintf(w, "# TYPE PortTripper_connections_active gauge\n")
		fmt.Fprintf(w, "PortTripper_connections_active %d\n", metrics.ActiveConns.Load())

		fmt.Fprintf(w, "# HELP PortTripper_ports_bound Total ports successfully bound\n")
		fmt.Fprintf(w, "# TYPE PortTripper_ports_bound gauge\n")
		fmt.Fprintf(w, "PortTripper_ports_bound %d\n", metrics.BoundPorts.Load())

		fmt.Fprintf(w, "# HELP PortTripper_ports_failed Total ports that failed to bind\n")
		fmt.Fprintf(w, "# TYPE PortTripper_ports_failed gauge\n")
		fmt.Fprintf(w, "PortTripper_ports_failed %d\n", metrics.FailedBinds.Load())

		fmt.Fprintf(w, "# HELP PortTripper_ports_skipped Total whitelisted ports skipped\n")
		fmt.Fprintf(w, "# TYPE PortTripper_ports_skipped gauge\n")
		fmt.Fprintf(w, "PortTripper_ports_skipped %d\n", metrics.SkippedPorts.Load())
	})
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	logger.Info("metrics server starting", map[string]any{"addr": addr})
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("metrics server error", map[string]any{"err": err})
	}
}


func main() {
	cfg := defaultConfig()

	flag.StringVar(&cfg.PortFile, "portfile", cfg.PortFile,
		"path to whitelist file; one port per line, '#' for comments")
	flag.IntVar(&cfg.StartPort, "startport", cfg.StartPort,
		"first (lowest) port to bind")
	flag.IntVar(&cfg.EndPort, "endport", cfg.EndPort,
		"last (highest) port to bind")
	flag.BoolVar(&cfg.Verbose, "verbose", cfg.Verbose,
		"enable verbose / debug logging")
	flag.BoolVar(&cfg.JSONLog, "jsonlog", cfg.JSONLog,
		"emit structured JSON log lines (for SIEM / log aggregators)")
	flag.IntVar(&cfg.HoldSeconds, "hold", cfg.HoldSeconds,
		"seconds to hold a dummy connection open before closing")
	flag.Int64Var(&cfg.MaxConnsTotal, "maxconns", cfg.MaxConnsTotal,
		"global cap on simultaneous connections (DoS protection)")
	flag.IntVar(&cfg.RateLimitPerIP, "ratelimit", cfg.RateLimitPerIP,
		"max new connections per second from a single source IP")
	flag.BoolVar(&cfg.EnableUDP, "udp", cfg.EnableUDP,
		"bind UDP ports in addition to TCP (enabled by default; use -udp=false to disable)")
	flag.StringVar(&cfg.MetricsAddr, "metrics", cfg.MetricsAddr,
		"address for Prometheus /metrics endpoint, e.g. :9100 (empty = disabled)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr,
			"PortTripper – dummy-port honeypot for anti-fingerprinting\n\nUsage:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nWhitelist file format:\n  # comment\n  80\n  443\n  8080\n")
	}

	if len(os.Args) >= 2 && os.Args[1] == "help" {
		flag.Usage()
		os.Exit(0)
	}
	flag.Parse()

	if cfg.StartPort < 1 || cfg.EndPort > 65535 || cfg.StartPort > cfg.EndPort {
		fmt.Fprintf(os.Stderr, "invalid port range %d-%d\n", cfg.StartPort, cfg.EndPort)
		os.Exit(1)
	}

	const maxHoldSeconds = 3600
	if cfg.HoldSeconds < 0 {
		cfg.HoldSeconds = 0
	} else if cfg.HoldSeconds > maxHoldSeconds {
		cfg.HoldSeconds = maxHoldSeconds
	}

	if cfg.MaxConnsTotal < 1 {
		cfg.MaxConnsTotal = 1
	}

	logger := &Logger{verbose: cfg.Verbose, jsonMode: cfg.JSONLog}
	logger.Info("PortTripper starting", map[string]any{
		"range":    fmt.Sprintf("%d-%d", cfg.StartPort, cfg.EndPort),
		"hold_sec": cfg.HoldSeconds,
		"udp":      cfg.EnableUDP,
		"maxconns": cfg.MaxConnsTotal,
	})

	created, err := ensureWhitelist(cfg.PortFile, cfg.StartPort, cfg.EndPort, logger)
	if err != nil {
		logger.Warn("could not create whitelist file",
			map[string]any{"file": cfg.PortFile, "err": err})
	} else if created {
		logger.Info("first run: whitelist written with currently-bound ports",
			map[string]any{"file": cfg.PortFile})
	}

	whitelist, err := loadWhitelist(cfg.PortFile)
	if err != nil {
		logger.Warn("could not load whitelist file (continuing without it)",
			map[string]any{"file": cfg.PortFile, "err": err})
	} else {
		logger.Info("whitelist loaded", map[string]any{
			"file":  cfg.PortFile,
			"ports": len(whitelist),
		})
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rl := newRateLimiter(cfg.RateLimitPerIP)

	if cfg.MetricsAddr != "" {
		host, _, err := net.SplitHostPort(cfg.MetricsAddr)
		if err == nil && host != "127.0.0.1" && host != "::1" && host != "localhost" {
			logger.Warn("metrics endpoint is not localhost-restricted; consider binding to 127.0.0.1",
				map[string]any{"addr": cfg.MetricsAddr})
		}
		go startMetricsServer(cfg.MetricsAddr, logger)
	}

	for port := cfg.StartPort; port <= cfg.EndPort; port++ {
		if _, skipped := whitelist[port]; skipped {
			metrics.SkippedPorts.Add(1)
			logger.Debug("skipping whitelisted port", map[string]any{"port": port})
			continue
		}
		p := port
		startTCPListener(ctx, p, cfg, rl, logger)
		if cfg.EnableUDP {
			startUDPListener(ctx, p, cfg, rl, logger)
		}
	}

	logger.Info("all listeners started", map[string]any{
		"bound":   metrics.BoundPorts.Load(),
		"skipped": metrics.SkippedPorts.Load(),
		"failed":  metrics.FailedBinds.Load(),
	})

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	logger.Info("shutting down", map[string]any{
		"signal":     sig.String(),
		"total_seen": metrics.TotalAccepted.Load(),
	})
	cancel()

	drainTimeout := time.Duration(cfg.HoldSeconds+1) * time.Second
	deadline := time.Now().Add(drainTimeout)
	for metrics.ActiveConns.Load() > 0 && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	logger.Info("exit", map[string]any{"active_conns_remaining": metrics.ActiveConns.Load()})
}