package service

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"zoraxy-waf-plugin/internal/config"
	"zoraxy-waf-plugin/internal/engine"
)

// Compares transport alone with unchanged HTTP/JSON, service and fake engine.
func BenchmarkLocalTransport(b *testing.B) {
	for _, network := range []string{"tcp", "unix"} {
		b.Run(network, func(b *testing.B) {
			dir := b.TempDir()
			c := config.Default()
			c.Mode = config.ModeBlock
			if err := config.Save(filepath.Join(dir, "config.json"), c); err != nil {
				b.Fatal(err)
			}
			s, err := New(Options{DataDir: dir, Build: func(config.Config) (engine.Engine, error) { return &fakeEngine{}, nil }})
			if err != nil {
				b.Fatal(err)
			}
			defer s.Close()
			address := "127.0.0.1:0"
			if network == "unix" {
				address = filepath.Join(dir, "ipc.sock")
			}
			listener, err := net.Listen(network, address)
			if err != nil {
				b.Fatal(err)
			}
			server := &http.Server{Handler: s.IPCHandler()}
			go server.Serve(listener)
			defer server.Close()
			tr := &http.Transport{Proxy: nil, MaxIdleConnsPerHost: 64}
			defer tr.CloseIdleConnections()
			url := "http://" + listener.Addr().String() + "/inspect"
			if network == "unix" {
				url = "http://127.0.0.1/inspect"
				tr.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "unix", address)
				}
			}
			client := &http.Client{Transport: tr}
			data, _ := json.Marshal(payload("POST", "/submit", "name=Alice&city=Berlin&quantity=2"))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				resp, err := client.Post(url, "application/json", bytes.NewReader(data))
				if err != nil {
					b.Fatal(err)
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode != 200 {
					b.Fatal(resp.StatusCode)
				}
			}
		})
	}
}
