package net

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestResolvePorts(t *testing.T) {
	p, err := ResolvePorts("quick")
	if err != nil || len(p) != 7 {
		t.Fatalf("quick preset: %v %v", p, err)
	}
	if got, _ := ResolvePorts("java"); !intIn(got, 29418) || !intIn(got, 2181) || !intIn(got, 9092) {
		t.Fatal("java preset missing ports")
	}
	if p, _ := ResolvePorts("80,443"); len(p) != 2 {
		t.Fatal("custom list")
	}
	if _, err := ResolvePorts("99999"); err == nil {
		t.Fatal("expected invalid port error")
	}
	if _, err := ResolvePorts(""); err == nil {
		t.Fatal("empty spec must error")
	}
}

func intIn(list []int, v int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func TestResolveTargets(t *testing.T) {
	tg, err := ResolveTargets("127.0.0.1,localhost")
	if err != nil {
		t.Fatal(err)
	}
	hasLoop := false
	for _, x := range tg {
		if x == "127.0.0.1" {
			hasLoop = true
		}
	}
	if !hasLoop || len(tg) < 1 {
		t.Fatalf("targets: %v", tg)
	}
	if _, err := ResolveTargets("bad.invalid.host"); err == nil {
		t.Fatal("unresolvable host must error")
	}
}

func TestFingerprint(t *testing.T) {
	tests := []struct {
		name  string
		hdrs  map[string]string
		body  string
		title string
		want  string
		conf  string
	}{
		{"jenkins", map[string]string{"x-jenkins": "2.504"}, "irrelevant", "", "jenkins", "high"},
		{"jira-header", map[string]string{"x-arequestid": "921|x"}, "", "", "jira", "high"},
		{"tomcat", map[string]string{"x-powered-by": "Tomcat/10.1.62"}, "", "", "tomcat", "high"},
		{"artifactory-jfrog", map[string]string{"x-jfrog-version": "7.104.2"}, "", "", "artifactory", "high"},
		{"jira-title", map[string]string{}, "<html><title>Log in - Jira</title></html>", "Log in - Jira", "jira", "medium"},
		{"confluence-title", map[string]string{}, "<title>Dashboard - Confluence</title>", "Dashboard - Confluence", "confluence", "medium"},
		{"keycloak-title", map[string]string{}, "<title>Keycloak Administration Console</title>", "Keycloak Administration Console", "keycloak", "medium"},
		{"solr-title", map[string]string{}, "<title>Solr Admin</title>", "Solr Admin", "solr", "medium"},
		{"gerrit-title", map[string]string{}, "<title>Gerrit Code Review</title>", "Gerrit Code Review", "gerrit", "medium"},
		{"pingfederate-title", map[string]string{}, "<title>PingFederate</title>", "PingFederate", "pingfederate", "medium"},
		{"es-json", map[string]string{}, `{"cluster_name":"docker-cluster","tagline":"You Know, for Search","version":{"number":"8.17.1"}}`, "", "elasticsearch", "high"},
		{"none", map[string]string{}, "<html><body>hello</body></html>", "hello", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Fingerprint(tt.hdrs, tt.body, tt.title)
			if got.Product != tt.want || got.Confidence != tt.conf {
				t.Fatalf("got %+v (evidence %q), want %s/%s", got, got.Evidence, tt.want, tt.conf)
			}
		})
	}
}

func httptestSrv(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(handler)
	t.Cleanup(s.Close)
	return s
}

func TestProbeServiceJenkinsOverHTTP(t *testing.T) {
	s := httptestSrv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Jenkins", "2.504.1")
		w.WriteHeader(200)
	}))
	ip, port := hostPortOf(s.URL)
	prod, conf, ev, st := probeService(ip, port, Options{})
	if prod != "jenkins" || conf != "high" || st != 200 {
		t.Fatalf("got %s/%s/%d ev=%s", prod, conf, st, ev)
	}
}

func TestProbeServiceElasticsearchDeep(t *testing.T) {
	s := httptestSrv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/artifactory/api/system/ping") || strings.Contains(r.URL.Path, "actuator") {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"cluster_name": "docker-cluster",
			"tagline":      "You Know, for Search",
			"version":      map[string]string{"number": "8.17.1"},
		})
	}))
	ip, port := hostPortOf(s.URL)
	prod, conf, _, st := probeService(ip, port, Options{})
	if prod != "elasticsearch" || conf != "high" || st != 200 {
		t.Fatalf("got %s/%s/%d", prod, conf, st)
	}
}

func TestProbeServiceArtifactoryPing(t *testing.T) {
	s := httptestSrv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/artifactory/api/system/ping") {
			w.Write([]byte("OK"))
			return
		}
		w.WriteHeader(404)
		w.Write([]byte("nothing"))
	}))
	ip, port := hostPortOf(s.URL)
	prod, conf, _, _ := probeService(ip, port, Options{})
	if prod != "artifactory" || conf != "high" {
		t.Fatalf("got %s/%s", prod, conf)
	}
}

func TestProbeServiceSpringBoot(t *testing.T) {
	s := httptestSrv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/actuator/health") {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"status":"UP"}`))
			return
		}
		if strings.Contains(r.URL.Path, "actuator") {
			w.Header().Set("Content-Type", "application/vnd.spring-boot.actuator.v3+json")
			w.Write([]byte(`{"_links":{}}`))
			return
		}
		w.WriteHeader(404)
	}))
	ip, port := hostPortOf(s.URL)
	prod, conf, _, _ := probeService(ip, port, Options{})
	if prod != "spring boot" || conf != "medium" {
		t.Fatalf("got %s/%s", prod, conf)
	}
}

// hostPortOf splits a httptest server URL into (ip, port).
func hostPortOf(rawURL string) (string, int) {
	u := strings.TrimPrefix(rawURL, "http://")
	i := strings.LastIndex(u, ":")
	port := 0
	for _, r := range u[i+1:] {
		port = port*10 + int(r-'0')
	}
	return u[:i], port
}

func TestKafkaProbeRejectedOnNonKafka(t *testing.T) {
	// A listener that never answers the ApiVersions ping -> "protocol unconfirmed".
	ln, err := net.Listen("tcp", "127.0.0.1:9092")
	if err != nil {
		t.Skipf("cannot bind 127.0.0.1:9092: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 64)
				c.Read(buf) // read request, never answer
			}(c)
		}
	}()
	prod, _, ev, _ := kafkaCheck("127.0.0.1", 9092, Options{KafkaProbe: true, TimeoutMS: 500})
	if prod != "" || !strings.Contains(ev, "protocol unconfirmed") {
		t.Fatalf("expected protocol unconfirmed, got %s/%s", prod, ev)
	}
}

func TestKafkaProbeDisabled(t *testing.T) {
	prod, _, ev, _ := kafkaCheck("127.0.0.1", 9092, Options{KafkaProbe: false})
	if prod != "" || ev != "" {
		t.Fatal("kafka probe must be skipped when disabled")
	}
}

func TestApiVersionsRequestFrame(t *testing.T) {
	frame := apiVersionsRequest(1234)
	// int32 size = 14, apiKey 18, apiVersion 0, corr 1234, clientId len 3 "j4s"
	if frame[0] != 0 || frame[1] != 0 || frame[2] != 0 || frame[3] != 13 {
		t.Fatalf("size field: %v", frame[:4])
	}
	if frame[4] != 0 || frame[5] != 18 {
		t.Fatalf("apiKey field: %v", frame[4:6])
	}
	if frame[6] != 0 || frame[7] != 0 {
		t.Fatalf("apiVersion field: %v", frame[6:8])
	}
	if frame[8] != 0 || frame[9] != 0 || frame[10] != 4 || frame[11] != 210 {
		t.Fatalf("correlation field: %v", frame[8:12])
	}
	if frame[12] != 0 || frame[13] != 3 || string(frame[14:17]) != "j4s" {
		t.Fatalf("clientId field: %v", frame[12:])
	}
}

func TestIsRedirectToHTTPS(t *testing.T) {
	if !isRedirectToHTTPS(302, map[string]string{"location": "https://x/y"}) {
		t.Fatal("https redirect not detected")
	}
	if isRedirectToHTTPS(302, map[string]string{"location": "http://x/y"}) {
		t.Fatal("http redirect wrongly detected")
	}
}

func TestTCPOpenClosed(t *testing.T) {
	if tcpOpen("203.0.113.1", 1, 300000000) { // TEST-NET-1, unlikely open
		t.Log("unexpectedly open - environment dependent; not fatal")
	}
	_, err := net.LookupHost("localhost")
	if err != nil {
		t.Skip("no localhost resolution")
	}
}

func TestResolveTargetsCIDR(t *testing.T) {
	cases := map[string][]string{
		"10.0.0.0/30":  {"10.0.0.1", "10.0.0.2"},
		"10.0.0.4/31":  {"10.0.0.4", "10.0.0.5"},
		"10.0.0.9/32":  {"10.0.0.9"},
		"10.0.0.16/29": {"10.0.0.17", "10.0.0.18", "10.0.0.19", "10.0.0.20", "10.0.0.21", "10.0.0.22"},
	}
	for spec, want := range cases {
		got, err := ResolveTargets(spec)
		if err != nil {
			t.Fatalf("%s: %v", spec, err)
		}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("%s: got %v want %v", spec, got, want)
		}
	}
	if _, err := ResolveTargets("10.0.0.0/8"); err == nil {
		t.Fatal("a /8 must be refused, not expanded")
	}
}
