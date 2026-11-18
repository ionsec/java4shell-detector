// Package net: inventory-only network scanner. It NEVER sends the
// Java4Shell trigger payload ("A"*64 + "=" or "A"*128 + "=") — sending the
// trigger crashes vulnerable JVMs (verified exit 134, hadrian.io). Only
// GET / probes and the Kafka ApiVersions ping below are emitted.
package net

import (
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Port presets.
var presets = map[string][]int{
	"quick": {443, 8443, 8080, 8081, 9000, 9200, 8983},
	"java": {443, 8443, 8080, 8081, 9000, 9200, 8983, 80, 8000, 8082, 8083,
		8084, 8085, 8086, 8087, 8088, 8089, 8181, 8888, 9001, 9003, 9020,
		9031, 9042, 9092, 9093, 9094, 9230, 9300, 9310, 9418, 9999, 5601,
		7070, 29418, 1883, 5672, 61616, 61613, 2181},
}

// ResolvePorts interprets a preset name or a custom comma list.
func ResolvePorts(spec string) ([]int, error) {
	if p, ok := presets[spec]; ok {
		return append([]int(nil), p...), nil
	}
	var out []int
	for _, tok := range strings.Split(spec, ",") {
		tok = strings.TrimSpace(tok)
		n, err := strconv.Atoi(tok)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("invalid port %q", tok)
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no ports in %q", spec)
	}
	return out, nil
}

// MaxExpandedTargets bounds CIDR expansion so a mistyped prefix (a /8, an
// IPv6 /64) cannot exhaust memory.
const MaxExpandedTargets = 1 << 20

// ResolveTargets expands hosts, CIDRs and comma lists into IPs.
func ResolveTargets(spec string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, tok := range strings.Split(spec, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if strings.Contains(tok, "/") {
			ip, ipnet, err := net.ParseCIDR(tok)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q", tok)
			}
			_ = ip
			// Network and broadcast addresses are skipped only on IPv4
			// blocks that have them (/30 and wider); /31 and /32 are
			// scanned in full.
			ones, bits := ipnet.Mask.Size()
			edges := ipnet.IP.To4() != nil && bits-ones >= 2
			for cur := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(cur); incIP(cur) {
				if edges && (skipNetAddr(cur, ipnet) || skipBroadcast(cur, ipnet)) {
					continue
				}
				s := cur.String()
				if !seen[s] {
					if len(out) >= MaxExpandedTargets {
						return nil, fmt.Errorf("target list exceeds %d addresses; split the range", MaxExpandedTargets)
					}
					seen[s] = true
					out = append(out, s)
				}
			}
			continue
		}
		if ip := net.ParseIP(tok); ip != nil {
			if !seen[tok] {
				seen[tok] = true
				out = append(out, tok)
			}
			continue
		}
		addrs, err := net.LookupHost(tok)
		if err != nil {
			return nil, fmt.Errorf("cannot resolve %q: %v", tok, err)
		}
		for _, a := range addrs {
			if !seen[a] {
				seen[a] = true
				out = append(out, a)
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no targets in %q", spec)
	}
	return out, nil
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

func skipNetAddr(ip net.IP, ipnet *net.IPNet) bool { return ip.Equal(ipnet.IP) }
func skipBroadcast(ip net.IP, ipnet *net.IPNet) bool {
	last := make(net.IP, len(ipnet.IP))
	copy(last, ipnet.IP)
	for i := range ipnet.Mask {
		if i < len(last) {
			last[i] |= ^ipnet.Mask[i]
		}
	}
	return ip.Equal(last)
}

// PortFinding is one open-port result with optional product fingerprint.
type PortFinding struct {
	IP         string `json:"ip"`
	Port       int    `json:"port"`
	Product    string `json:"product"`
	Confidence string `json:"confidence,omitempty"`
	Evidence   string `json:"evidence,omitempty"`
	HTTPStatus int    `json:"http_status,omitempty"`
}

type netReport struct {
	Targets []PortFinding `json:"targets"`
	Summary struct {
		Probed         int `json:"probed"`
		Open           int `json:"open"`
		ReachedHTTP    int `json:"reached_http"`
		ProductMatches int `json:"product_matches"`
	} `json:"summary"`
	AssessmentNote string `json:"assessment_note"`
}

// Options controls a scan run.
type Options struct {
	Targets     string
	Ports       string
	Concurrency int
	TimeoutMS   int
	InsecureTLS bool
	MaxHosts    int
	KafkaProbe  bool
}

// Run performs the inventory-only scan.
func Run(opts Options) (string, error) {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 128
	}
	if opts.TimeoutMS <= 0 {
		opts.TimeoutMS = 800
	}
	targets, err := ResolveTargets(opts.Targets)
	if err != nil {
		return "", err
	}
	if opts.MaxHosts > 0 && len(targets) > opts.MaxHosts {
		targets = targets[:opts.MaxHosts]
	}
	ports, err := ResolvePorts(opts.Ports)
	if err != nil {
		return "", err
	}
	report := &netReport{AssessmentNote: "inventory only: no payload beyond HTTP GET/ and the Kafka ApiVersions ping was sent; the Java4Shell trigger (64/128 x 'A' + '=') is never transmitted because it crashes vulnerable JVMs (exit 134)."}
	type job struct {
		ip   string
		port int
	}
	jobs := make(chan job)
	results := make(chan PortFinding, 4096)
	var wg sync.WaitGroup
	for i := 0; i < opts.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if tcpOpen(j.ip, j.port, time.Duration(opts.TimeoutMS)*time.Millisecond) {
					results <- PortFinding{IP: j.ip, Port: j.port}
				}
			}
		}()
	}
	total := len(targets) * len(ports)
	report.Summary.Probed = total
	go func() {
		for _, ip := range targets {
			for _, p := range ports {
				jobs <- job{ip, p}
			}
		}
		close(jobs)
	}()
	go func() {
		wg.Wait()
		close(results)
	}()
	var findings []PortFinding
	for r := range results {
		r.Product, r.Confidence, r.Evidence, r.HTTPStatus = probeService(r.IP, r.Port, opts)
		findings = append(findings, r)
		report.Summary.Open++
		if r.Product != "" {
			report.Summary.ProductMatches++
		}
		if r.Product != "" || r.HTTPStatus != 0 {
			report.Summary.ReachedHTTP++
		}
	}
	// stable order
	sortFindings(findings)
	report.Targets = findings
	report.Summary.ReachedHTTP = countHTTP(findings)
	b, _ := json.MarshalIndent(report, "", "  ")
	return string(b), nil
}

func countHTTP(fs []PortFinding) int {
	n := 0
	for _, f := range fs {
		if f.HTTPStatus != 0 || (f.Product != "" && f.Port == 29418) {
			n++
		}
	}
	return n
}

func sortFindings(fs []PortFinding) {
	for i := 1; i < len(fs); i++ {
		for j := i; j > 0 && lessFinding(fs[j], fs[j-1]); j-- {
			fs[j], fs[j-1] = fs[j-1], fs[j]
		}
	}
}

func lessFinding(a, b PortFinding) bool {
	if a.IP != b.IP {
		return a.IP < b.IP
	}
	return a.Port < b.Port
}

// tcpOpen does a plain TCP connect sweep (no payload on closed ports).
func tcpOpen(ip string, port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// probeService attempts HTTP GET / (falling back to TLS) and fingerprints.
func probeService(ip string, port int, opts Options) (product, confidence, evidence string, status int) {
	if port == 29418 {
		return gerritSSHBanner(ip, port, opts)
	}
	scheme := "http"
	if port == 443 {
		scheme = "https"
	}
	base := fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(ip, strconv.Itoa(port)))
	body, hdrs, st, err := httpGet(base, opts)
	if err != nil {
		// binary protocol or TLS-alerted port: retry over TLS
		body2, hdrs2, st2, err2 := httpGetWithTLS(fmt.Sprintf("https://%s", net.JoinHostPort(ip, strconv.Itoa(port))), opts)
		if err2 != nil {
			return kafkaCheck(ip, port, opts)
		}
		body, hdrs, st = body2, hdrs2, st2
	} else if isRedirectToHTTPS(st, hdrs) {
		body2, hdrs2, st2, err2 := httpGetWithTLS(fmt.Sprintf("https://%s", net.JoinHostPort(ip, strconv.Itoa(port))), opts)
		if err2 == nil {
			body, hdrs, st = body2, hdrs2, st2
		}
	}
	if st == 0 {
		return kafkaCheck(ip, port, opts)
	}
	status = st
	title := extractTitle(body)
	if p := Fingerprint(hdrs, body, title); p.Product != "" {
		return p.Product, p.Confidence, p.Evidence, status
	}
	// Deep probes for well-known paths.
	if extra := deepProbe(base, opts); extra.Product != "" {
		return extra.Product, extra.Confidence, extra.Evidence, status
	}
	return "", "", "", status
}

func isRedirectToHTTPS(st int, hdrs map[string]string) bool {
	if st >= 300 && st < 400 {
		loc := strings.ToLower(hdrs["location"])
		return strings.HasPrefix(loc, "https://")
	}
	return false
}

func httpGet(base string, opts Options) (string, map[string]string, int, error) {
	return doGet(base, false, opts)
}

func httpGetWithTLS(base string, opts Options) (string, map[string]string, int, error) {
	return doGet(base, true, opts)
}

var redirectPolicy = func(req *http.Request, via []*http.Request) error {
	return http.ErrUseLastResponse // do not follow; record as-is
}

func doGet(base string, forceTLS bool, opts Options) (string, map[string]string, int, error) {
	client := &http.Client{
		Timeout:       5 * time.Second,
		CheckRedirect: redirectPolicy,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: opts.InsecureTLS},
		},
	}
	u, _ := url.Parse(base)
	if u.Path == "" {
		base = base + "/"
	}
	req, err := http.NewRequest("GET", base, nil)
	if err != nil {
		return "", nil, 0, err
	}
	req.Host = u.Host
	req.Header.Set("User-Agent", "ionsec-java4shell-detector/1.0")
	req.Header.Set("Accept", "*/*")
	resp, err := client.Do(req)
	if err != nil {
		return "", nil, 0, err
	}
	defer resp.Body.Close()
	hdrs := map[string]string{}
	for k, v := range resp.Header {
		if len(v) > 0 {
			hdrs[strings.ToLower(k)] = v[0]
		}
	}
	hdrs["location"] = resp.Header.Get("Location")
	n := int64(4096)
	var body string
	if resp.ContentLength != 0 {
		b, err := io.ReadAll(io.LimitReader(resp.Body, n))
		if err != nil && len(b) == 0 {
			return "", hdrs, resp.StatusCode, err
		}
		body = string(b)
	}
	return body, hdrs, resp.StatusCode, nil
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func extractTitle(body string) string {
	if m := titleRe.FindStringSubmatch(body); m != nil {
		return strings.TrimSpace(m[1])
	}
	return ""
}

// Fingerprint maps canned headers/body to product names.
type fpResult struct {
	Product    string
	Confidence string
	Evidence   string
}

func Fingerprint(hdrs map[string]string, body, title string) fpResult {
	_ = body
	if v, ok := hdrs["x-jenkins"]; ok && v != "" {
		return fpResult{"jenkins", "high", "X-Jenkins: " + v}
	}
	if _, ok := hdrs["x-arequestid"]; ok {
		return fpResult{"jira", "high", "X-AREQUESTID header present"}
	}
	if strings.Contains(hdrs["x-powered-by"], "Tomcat") {
		return fpResult{"tomcat", "high", "X-Powered-By: " + hdrs["x-powered-by"]}
	}
	if _, ok := hdrs["x-artifactory-id"]; ok {
		return fpResult{"artifactory", "high", "X-Artifactory-Id header present"}
	}
	if v := hdrs["x-jfrog-version"]; v != "" {
		return fpResult{"artifactory", "high", "X-JFrog-Version: " + v}
	}
	if ev := esFingerprint(body); ev != "" {
		return fpResult{"elasticsearch", "high", ev}
	}
	return titleFingerprint(title)
}

func esFingerprint(body string) string {
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		return ""
	}
	if _, ok := m["cluster_name"]; ok {
		if tagline, ok := m["tagline"].(string); ok && strings.Contains(tagline, "You Know, for Search") {
			ver := ""
			if vm, ok := m["version"].(map[string]interface{}); ok {
				if n, ok := vm["number"].(string); ok {
					ver = " version=" + n
				}
			}
			return "JSON cluster_name + tagline" + ver
		}
	}
	return ""
}

func titleFingerprint(title string) fpResult {
	t := strings.ToLower(title)
	switch {
	case strings.Contains(t, "jira"):
		return fpResult{"jira", "medium", "html title: " + title}
	case strings.Contains(t, "confluence"):
		return fpResult{"confluence", "medium", "html title: " + title}
	case strings.Contains(t, "keycloak"):
		return fpResult{"keycloak", "medium", "html title: " + title}
	case strings.Contains(t, "solr admin"):
		return fpResult{"solr", "medium", "html title: " + title}
	case strings.Contains(t, "gerrit code review"):
		return fpResult{"gerrit", "medium", "html title: " + title}
	case strings.Contains(t, "pingfederate"):
		return fpResult{"pingfederate", "medium", "html title: " + title}
	case strings.Contains(t, "spinnaker"):
		return fpResult{"spinnaker", "medium", "html title: " + title}
	}
	return fpResult{}
}

// deepProbe checks known deep paths.
func deepProbe(base string, opts Options) fpResult {
	if body, _, _, err := doGet(base+"/artifactory/api/system/ping", false, opts); err == nil {
		if strings.TrimSpace(body) == "OK" {
			return fpResult{"artifactory", "high", "/artifactory/api/system/ping returned OK"}
		}
	}
	if _, hdrs, _, err := doGet(base+"/actuator", false, opts); err == nil {
		if b, _, _, err2 := doGet(base+"/actuator/health", false, opts); err2 == nil {
			var m map[string]interface{}
			if json.Unmarshal([]byte(b), &m) == nil {
				if _, ok := m["status"]; ok {
					return fpResult{"spring boot", "medium", "/actuator/health JSON status present"}
				}
			}
		}
		if strings.Contains(hdrs["content-type"], "json") {
			return fpResult{"spring boot", "medium", "/actuator JSON _links"}
		}
	}
	return fpResult{}
}

// kafkaCheck confirms the Kafka protocol with an ApiVersions v0 ping
// (port 9092 only; --kafka-probe, default on).
func kafkaCheck(ip string, port int, opts Options) (string, string, string, int) {
	if port != 9092 || !opts.KafkaProbe {
		return "", "", "", 0
	}
	payload := apiVersionsRequest(1234)
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "9092"), time.Duration(opts.TimeoutMS)*time.Millisecond)
	if err != nil {
		return "", "", "", 0
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		return "", "", "port 9092 open, protocol unconfirmed", 0
	}
	buf := make([]byte, 8)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return "", "", "port 9092 open, protocol unconfirmed", 0
	}
	corr := binary.BigEndian.Uint32(buf[4:8])
	if corr == 1234 {
		return "kafka broker", "high", "Kafka ApiVersions v0 ping echoed correlationId 1234", 0
	}
	return "", "", "port 9092 open, protocol unconfirmed", 0
}

// apiVersionsRequest builds an ApiVersions v0 request frame:
// int32 size + int16 apiKey=18 + int16 apiVersion=0 + int32 correlationId + int16 clientIdLen + clientId.
func apiVersionsRequest(correlationID uint32) []byte {
	bodyLen := 2 + 2 + 4 + 2 + 3 // apiKey + apiVersion + correlationId + clientIdLen + "j4s"
	frame := make([]byte, 0, 4+bodyLen)
	b4 := make([]byte, 4)
	binary.BigEndian.PutUint32(b4, uint32(bodyLen))
	frame = append(frame, b4...)
	binary.BigEndian.PutUint16(b4[:2], 18)
	frame = append(frame, b4[:2]...)
	binary.BigEndian.PutUint16(b4[:2], 0)
	frame = append(frame, b4[:2]...)
	binary.BigEndian.PutUint32(b4, correlationID)
	frame = append(frame, b4...)
	binary.BigEndian.PutUint16(b4[:2], 3)
	frame = append(frame, b4[:2]...)
	return append(frame, 'j', '4', 's')
}

// gerritSSHBanner reads an SSH banner on 29418.
func gerritSSHBanner(ip string, port int, opts Options) (string, string, string, int) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), time.Duration(opts.TimeoutMS)*time.Millisecond)
	if err != nil {
		return "", "", "", 0
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	banner := strings.TrimSpace(string(buf[:n]))
	if err != nil && n == 0 {
		return "", "", "", 0
	}
	if strings.Contains(banner, "GerritCodeReview") || strings.Contains(banner, "SSH") {
		return "gerrit", "high", "SSH banner on 29418: " + banner, 0
	}
	return "", "", "", 0
}
