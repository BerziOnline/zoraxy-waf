package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"zoraxy-waf-plugin/internal/admin"
	"zoraxy-waf-plugin/internal/branding"
	"zoraxy-waf-plugin/internal/config"
	"zoraxy-waf-plugin/internal/engine/coraza"
	"zoraxy-waf-plugin/internal/service"
	"zoraxy-waf-plugin/internal/wire"
	"zoraxy-waf-plugin/internal/zoraxy"
)

const pluginID = "org.zoraxy.waf"

// dataDir is where config.json and the records live: ZORAXY_WAF_DATA_DIR or
// data/ next to the binary.
func dataDir(exe string) string {
	if dir := os.Getenv("ZORAXY_WAF_DATA_DIR"); dir != "" {
		return dir
	}
	return filepath.Join(filepath.Dir(exe), "data")
}

// sniffBodyKB reads the saved settings: Zoraxy asks once at its start how
// much body to send, so it gets the largest size any host is set to.
func sniffBodyKB() int {
	exe, err := os.Executable()
	if err != nil {
		return config.Default().SniffBodyKB()
	}
	c, err := config.Load(filepath.Join(dataDir(exe), "config.json"))
	if errors.Is(err, fs.ErrNotExist) {
		return config.Default().SniffBodyKB()
	}
	if err != nil {
		// Unreadable settings: ask for the most, the plugin cuts per host.
		return 1024
	}
	return c.SniffBodyKB()
}

// introspect describes the plugin to Zoraxy. bodyKB is the request body
// prefix Zoraxy sends with each sniff call.
func introspect(bodyKB int) wire.IntroSpect {
	return wire.IntroSpect{DynamicCaptureSniffBodyKB: bodyKB, ID: pluginID, Name: "Zoraxy WAF", Author: "Zoraxy WAF contributors", AuthorContact: "https://github.com/BerziOnline/zoraxy-waf/issues", URL: "https://github.com/BerziOnline/zoraxy-waf", Description: "Web application firewall (Coraza + OWASP CRS). Inspects requests before routing via the dynamic capture sniffer; allowed traffic continues normal Zoraxy routing.", Type: wire.PluginTypeRouter, VersionMajor: 0, VersionMinor: 1, DynamicCaptureSniff: "/sniff", DynamicCaptureIngress: "/capture", UIPath: "/ui", DashboardWidget: "/api/widget", StaticCapturePaths: []wire.StaticCaptureRule{}, SubscriptionsEvents: map[string]string{}, PermittedAPIEndpoints: []wire.PermittedAPIEndpoint{
		{Method: "GET", Endpoint: zoraxy.EndpointProxyList, Reason: "Read the HTTP proxy routes to list your hosts in the WAF (read-only)"},
		{Method: "GET", Endpoint: zoraxy.EndpointPluginGroups, Reason: "See which route tags send traffic through the WAF (read-only)"},
	}}
}
func routes(s *service.Service, stop func()) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/inspect", s.IPCHandler())
	mux.Handle("/sniff/", s.IPCHandler())
	mux.Handle("/capture/", s.IPCHandler())
	mux.Handle("/ui/", admin.Handler(s))
	mux.HandleFunc("/ui/term", func(w http.ResponseWriter, r *http.Request) {
		// SDK lifecycle endpoint: called directly by the core, never from a UI.
		if !service.LoopbackHost(r.Host) || r.Header.Get("Origin") != "" || r.Header.Get("Sec-Fetch-Site") != "" || r.Header.Get("X-Zoraxy-Csrf") != "" {
			http.Error(w, "Core lifecycle only", 403)
			return
		}
		if r.Method != "GET" {
			http.Error(w, "GET required", 405)
			return
		}
		w.WriteHeader(200)
		stop()
	})
	return mux
}
func run(args []string, out io.Writer) error {
	for _, arg := range args {
		if arg == "-introspect" {
			return json.NewEncoder(out).Encode(introspect(sniffBodyKB()))
		}
	}
	cfg, err := wire.ParseConfigureArgs(args)
	if err != nil {
		return err
	}
	if !coraza.NoDiskSpool {
		return errors.New("unsafe build: rebuild with -tags no_fs_access to prevent request-body disk spooling")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	dir := dataDir(exe)
	// Zoraxy shows <plugin root>/icon.png; ship it from the binary so a manual
	// install needs no extra file. Failure only costs the logo, never the WAF.
	if _, err := branding.Install(filepath.Dir(exe)); err != nil {
		fmt.Fprintln(out, "icon.png not written:", err)
	}
	s, err := service.New(service.Options{DataDir: dir})
	if err != nil {
		return fmt.Errorf("start WAF: %w", err)
	}
	defer s.Close()
	if c := zoraxy.New(cfg.ZoraxyPort, cfg.APIKey, pluginID); c != nil {
		s.SetRouteSource(c)
	} else {
		fmt.Fprintln(out, "Zoraxy gave no plugin API key; the host list shows hosts from traffic and overrides only")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	server := &http.Server{Addr: "127.0.0.1:" + strconv.Itoa(cfg.Port), Handler: routes(s, cancel), ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 35 * time.Second, WriteTimeout: 35 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 64 << 10}
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-ctx.Done()
		shutdown, c := context.WithTimeout(context.Background(), 4*time.Second)
		defer c()
		server.Shutdown(shutdown)
	}()
	fmt.Fprintln(out, "Zoraxy WAF ready on loopback; configure through the Zoraxy plugin UI")
	err = server.ListenAndServe()
	cancel()
	<-done
	if !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		log.Fatal(err)
	}
}
