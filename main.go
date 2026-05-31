package main

import (
	"bufio"
	"context"
	crand "crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
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
	PortFile         string
	StartPort        int
	EndPort          int
	Verbose          bool
	JSONLog          bool
	HoldSeconds      int
	MaxConnsTotal    int64
	RateLimitPerIP   int
	EnableUDP        bool
	MetricsAddr      string
	MaxConnsPerIP    int64
	GlobalAcceptRate int
	AcceptBufBytes   int
	ReadTimeout      time.Duration
	MaxRLBuckets     int
	MaxPorts         int
}

func defaultConfig() Config {
	return Config{
		PortFile:         "whitelist.txt",
		StartPort:        1024,
		EndPort:          65000,
		Verbose:          false,
		JSONLog:          false,
		HoldSeconds:      2,
		MaxConnsTotal:    10_000,
		RateLimitPerIP:   5,
		EnableUDP:        true,
		MetricsAddr:      "",
		MaxConnsPerIP:    64,
		GlobalAcceptRate: 5_000,
		AcceptBufBytes:   0,
		ReadTimeout:      5 * time.Second,
		MaxRLBuckets:     100_000,
		MaxPorts:         1024,
	}
}

type Metrics struct {
	TotalAccepted   atomic.Int64
	TotalRejected   atomic.Int64
	ActiveConns     atomic.Int64
	SkippedPorts    atomic.Int64
	BoundPorts      atomic.Int64
	FailedBinds     atomic.Int64
	GlobalThrottled atomic.Int64
	PerIPThrottled  atomic.Int64
}

var metrics Metrics

type perIPConns struct {
	mu    sync.Mutex
	count map[string]int64
	limit int64
}

func newPerIPConns(limit int64) *perIPConns {
	if limit < 1 {
		limit = 1
	}
	return &perIPConns{count: make(map[string]int64), limit: limit}
}

func (p *perIPConns) acquire(ip string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.count[ip] >= p.limit {
		return false
	}
	p.count[ip]++
	return true
}

func (p *perIPConns) release(ip string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if c := p.count[ip]; c <= 1 {
		delete(p.count, ip)
	} else {
		p.count[ip] = c - 1
	}
}

type globalRate struct {
	mu     sync.Mutex
	tokens float64
	max    float64
	rate   float64
	last   time.Time
}

func newGlobalRate(perSec int) *globalRate {
	if perSec < 1 {
		perSec = 1
	}
	return &globalRate{
		tokens: float64(perSec),
		max:    float64(perSec),
		rate:   float64(perSec),
		last:   time.Now(),
	}
}

func (g *globalRate) allow() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(g.last).Seconds()
	if elapsed < 0 {
		elapsed = 0
	}
	g.tokens += elapsed * g.rate
	if g.tokens > g.max {
		g.tokens = g.max
	}
	g.last = now
	if g.tokens < 1 {
		return false
	}
	g.tokens--
	return true
}

const defaultMaxRateLimiterBuckets = 100_000

type ipBucket struct {
	tokens    float64
	lastRefil time.Time
}

type RateLimiter struct {
	mu         sync.Mutex
	buckets    map[string]*ipBucket
	limit      int
	maxBuckets int
}

func newRateLimiter(limit, maxBuckets int) *RateLimiter {
	if limit < 1 {
		limit = 1
	}
	if maxBuckets < 1 {
		maxBuckets = defaultMaxRateLimiterBuckets
	}
	rl := &RateLimiter{
		buckets:    make(map[string]*ipBucket),
		limit:      limit,
		maxBuckets: maxBuckets,
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
		if len(rl.buckets) >= rl.maxBuckets {
			return false
		}
		b = &ipBucket{tokens: float64(rl.limit), lastRefil: now}
		rl.buckets[ip] = b
	}
	elapsed := now.Sub(b.lastRefil).Seconds()
	if elapsed < 0 {
		elapsed = 0
		b.lastRefil = now
	}
	if elapsed > 0 {
		b.tokens += elapsed * float64(rl.limit)
		if b.tokens > float64(rl.limit) {
			b.tokens = float64(rl.limit)
		}
		b.lastRefil = now
	}
	if b.tokens < 1 {
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
	fmt.Fprintln(w, "# PortTripper - port whitelist (auto-generated on first run)")
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

func cryptoIntn(n int) int {
	if n <= 0 {
		panic("cryptoIntn: n must be positive")
	}
	max := big.NewInt(int64(n))
	v, err := crand.Int(crand.Reader, max)
	if err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return int(v.Int64())
}

func selectPorts(start, end int, whitelist map[int]struct{}, maxPorts int) (chosen []int, sampled bool) {
	candidates := make([]int, 0, end-start+1)
	for p := start; p <= end; p++ {
		if _, skip := whitelist[p]; skip {
			continue
		}
		candidates = append(candidates, p)
	}

	if maxPorts <= 0 || len(candidates) <= maxPorts {
		return candidates, false
	}

	for i := 0; i < maxPorts; i++ {
		j := i + cryptoIntn(len(candidates)-i)
		candidates[i], candidates[j] = candidates[j], candidates[i]
	}
	chosen = candidates[:maxPorts]
	sort.Ints(chosen)
	return chosen, true
}

type listenerDeps struct {
	cfg    Config
	rl     *RateLimiter
	gr     *globalRate
	perIP  *perIPConns
	logger *Logger

	closersMu sync.Mutex
	closers   []io.Closer
}

func (d *listenerDeps) track(c io.Closer) {
	d.closersMu.Lock()
	d.closers = append(d.closers, c)
	d.closersMu.Unlock()
}

func (d *listenerDeps) closeAll() {
	d.closersMu.Lock()
	cs := d.closers
	d.closers = nil
	d.closersMu.Unlock()
	for _, c := range cs {
		_ = c.Close()
	}
}

func startTCPListener(ctx context.Context, port int, d *listenerDeps) {
	addr := fmt.Sprintf(":%d", port)
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		metrics.FailedBinds.Add(1)
		d.logger.Debug("TCP bind failed", map[string]any{"port": port, "err": err})
		return
	}
	metrics.BoundPorts.Add(1)
	d.logger.Debug("TCP listening", map[string]any{"port": port})

	d.track(ln)
	go acceptLoopTCP(ctx, ln, port, d)
}

func acceptLoopTCP(ctx context.Context, ln net.Listener, port int, d *listenerDeps) {
	backoff := 5 * time.Millisecond
	const maxBackoff = 1 * time.Second
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			d.logger.Debug("accept error", map[string]any{"port": port, "err": err})
			time.Sleep(backoff)
			if backoff < maxBackoff {
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
			}
			continue
		}
		backoff = 5 * time.Millisecond

		if !d.gr.allow() {
			metrics.GlobalThrottled.Add(1)
			metrics.TotalRejected.Add(1)
			conn.Close()
			continue
		}

		srcIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		srcIP = normalizeIP(srcIP)

		if !d.rl.Allow(srcIP) {
			metrics.TotalRejected.Add(1)
			d.logger.Warn("rate limit exceeded", map[string]any{"src": srcIP, "port": port})
			conn.Close()
			continue
		}

		if !reserveGlobalSlot(d.cfg.MaxConnsTotal) {
			metrics.TotalRejected.Add(1)
			conn.Close()
			continue
		}

		if !d.perIP.acquire(srcIP) {
			metrics.PerIPThrottled.Add(1)
			metrics.TotalRejected.Add(1)
			metrics.ActiveConns.Add(-1)
			conn.Close()
			continue
		}

		metrics.TotalAccepted.Add(1)
		d.logger.Info("connection", map[string]any{"src": srcIP, "port": port, "proto": "tcp"})

		go handleTCPConn(ctx, conn, srcIP, d)
	}
}

func reserveGlobalSlot(max int64) bool {
	for {
		cur := metrics.ActiveConns.Load()
		if cur >= max {
			return false
		}
		if metrics.ActiveConns.CompareAndSwap(cur, cur+1) {
			return true
		}
	}
}

func handleTCPConn(ctx context.Context, c net.Conn, srcIP string, d *listenerDeps) {
	defer func() {
		c.Close()
		metrics.ActiveConns.Add(-1)
		d.perIP.release(srcIP)
	}()

	hold := time.Duration(d.cfg.HoldSeconds) * time.Second
	_ = c.SetDeadline(time.Now().Add(hold + d.cfg.ReadTimeout))

	if d.cfg.AcceptBufBytes > 0 {
		buf := make([]byte, d.cfg.AcceptBufBytes)
		_ = c.SetReadDeadline(time.Now().Add(d.cfg.ReadTimeout))
		_, _ = c.Read(buf)
	}

	select {
	case <-time.After(hold):
	case <-ctx.Done():
	}
}

func startUDPListener(ctx context.Context, port int, d *listenerDeps) {
	addr := fmt.Sprintf(":%d", port)
	var lc net.ListenConfig
	conn, err := lc.ListenPacket(ctx, "udp", addr)
	if err != nil {
		metrics.FailedBinds.Add(1)
		d.logger.Debug("UDP bind failed", map[string]any{"port": port, "err": err})
		return
	}
	metrics.BoundPorts.Add(1)

	d.track(conn)
	go func() {
		buf := make([]byte, 512)
		backoff := 5 * time.Millisecond
		const maxBackoff = 1 * time.Second
		for {
			_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
			_, src, err := conn.ReadFrom(buf)
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
				}
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				time.Sleep(backoff)
				if backoff < maxBackoff {
					backoff *= 2
					if backoff > maxBackoff {
						backoff = maxBackoff
					}
				}
				continue
			}
			backoff = 5 * time.Millisecond

			if !d.gr.allow() {
				metrics.GlobalThrottled.Add(1)
				metrics.TotalRejected.Add(1)
				continue
			}
			srcIP, _, _ := net.SplitHostPort(src.String())
			srcIP = normalizeIP(srcIP)
			if !d.rl.Allow(srcIP) {
				metrics.TotalRejected.Add(1)
				continue
			}
			metrics.TotalAccepted.Add(1)
			d.logger.Debug("connection", map[string]any{"src": srcIP, "port": port, "proto": "udp"})
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

		fmt.Fprintf(w, "# HELP PortTripper_global_throttled_total Accepts dropped by global rate ceiling\n")
		fmt.Fprintf(w, "# TYPE PortTripper_global_throttled_total counter\n")
		fmt.Fprintf(w, "PortTripper_global_throttled_total %d\n", metrics.GlobalThrottled.Load())

		fmt.Fprintf(w, "# HELP PortTripper_perip_throttled_total Accepts dropped by per-IP conn cap\n")
		fmt.Fprintf(w, "# TYPE PortTripper_perip_throttled_total counter\n")
		fmt.Fprintf(w, "PortTripper_perip_throttled_total %d\n", metrics.PerIPThrottled.Load())

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
		MaxHeaderBytes:    16 << 10,
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
		"address for Prometheus /metrics endpoint, e.g. 127.0.0.1:9100 (empty = disabled)")
	flag.Int64Var(&cfg.MaxConnsPerIP, "maxconns-per-ip", cfg.MaxConnsPerIP,
		"cap on simultaneous TCP connections from a single source IP")
	flag.IntVar(&cfg.GlobalAcceptRate, "global-rate", cfg.GlobalAcceptRate,
		"hard global ceiling on new connections per second across all ports")
	flag.IntVar(&cfg.AcceptBufBytes, "drain-bytes", cfg.AcceptBufBytes,
		"bytes to read and discard per TCP connection (0 = none; bounded anti-amplification)")
	flag.IntVar(&cfg.MaxPorts, "maxports", cfg.MaxPorts,
		"max ports to bind; if the range is larger, a random subset is chosen (0 = bind whole range)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr,
			"PortTripper - dummy-port honeypot for anti-fingerprinting\n\nUsage:\n")
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
	if cfg.MaxConnsPerIP < 1 {
		cfg.MaxConnsPerIP = 1
	}
	if cfg.GlobalAcceptRate < 1 {
		cfg.GlobalAcceptRate = 1
	}
	if cfg.AcceptBufBytes < 0 {
		cfg.AcceptBufBytes = 0
	} else if cfg.AcceptBufBytes > 64<<10 {
		cfg.AcceptBufBytes = 64 << 10
	}
	if cfg.MaxPorts < 0 {
		cfg.MaxPorts = 0
	}

	logger := &Logger{verbose: cfg.Verbose, jsonMode: cfg.JSONLog}
	logger.Info("PortTripper starting", map[string]any{
		"range":           fmt.Sprintf("%d-%d", cfg.StartPort, cfg.EndPort),
		"hold_sec":        cfg.HoldSeconds,
		"udp":             cfg.EnableUDP,
		"maxconns":        cfg.MaxConnsTotal,
		"maxconns_per_ip": cfg.MaxConnsPerIP,
		"global_rate":     cfg.GlobalAcceptRate,
		"maxports":        cfg.MaxPorts,
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

	d := &listenerDeps{
		cfg:    cfg,
		rl:     newRateLimiter(cfg.RateLimitPerIP, cfg.MaxRLBuckets),
		gr:     newGlobalRate(cfg.GlobalAcceptRate),
		perIP:  newPerIPConns(cfg.MaxConnsPerIP),
		logger: logger,
	}

	if cfg.MetricsAddr != "" {
		host, _, err := net.SplitHostPort(cfg.MetricsAddr)
		if err == nil && host != "127.0.0.1" && host != "::1" && host != "localhost" {
			logger.Warn("metrics endpoint is not localhost-restricted; consider binding to 127.0.0.1",
				map[string]any{"addr": cfg.MetricsAddr})
		}
		go startMetricsServer(cfg.MetricsAddr, logger)
	}

	for p := range whitelist {
		if p >= cfg.StartPort && p <= cfg.EndPort {
			metrics.SkippedPorts.Add(1)
		}
	}

	chosen, sampled := selectPorts(cfg.StartPort, cfg.EndPort, whitelist, cfg.MaxPorts)
	if sampled {
		logger.Info("port range exceeds max; binding a random subset",
			map[string]any{
				"range_size": cfg.EndPort - cfg.StartPort + 1,
				"max_ports":  cfg.MaxPorts,
				"selected":   len(chosen),
			})
	}

	for _, port := range chosen {
		startTCPListener(ctx, port, d)
		if cfg.EnableUDP {
			startUDPListener(ctx, port, d)
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
	d.closeAll()

	drainTimeout := time.Duration(cfg.HoldSeconds+1)*time.Second + cfg.ReadTimeout
	deadline := time.Now().Add(drainTimeout)
	for metrics.ActiveConns.Load() > 0 && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	logger.Info("exit", map[string]any{"active_conns_remaining": metrics.ActiveConns.Load()})
}