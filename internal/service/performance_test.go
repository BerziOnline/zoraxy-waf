package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"zoraxy-waf-plugin/internal/config"
	"zoraxy-waf-plugin/internal/engine"
	"zoraxy-waf-plugin/internal/engine/coraza"
	"zoraxy-waf-plugin/internal/wire"
)

func BenchmarkLayers(b *testing.B) {
	for _, size := range []int{33, 4096, 65536} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			p := payload("POST", "/submit", "name=Alice&city=Berlin&quantity=2")
			p.Body = append([]byte("data="), bytes.Repeat([]byte("a"), size-5)...)
			raw, _ := json.Marshal(p)
			b.Run("Codec", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					d, err := json.Marshal(p)
					if err != nil {
						b.Fatal(err)
					}
					if _, err = wire.DecodeInspectPayload(bytes.NewReader(d), 2<<20); err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run("Coraza", func(b *testing.B) {
				e, err := coraza.New([]int{1}, 5)
				if err != nil {
					b.Fatal(err)
				}
				defer e.Close()
				req := &engine.Request{Method: p.Method, RawURI: p.RequestURI, Proto: p.Proto, Host: p.Host, ClientIP: p.ClientIP, Header: p.Header, Body: p.Body}
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					d, err := e.Inspect(context.Background(), req, engine.Options{ParanoiaLevel: 1})
					if err != nil || d.Interrupted {
						b.Fatalf("%+v %v", d, err)
					}
				}
			})
			for _, network := range []bool{false, true} {
				label := "ServiceFake"
				if network {
					label = "IPCFake"
				}
				b.Run(label, func(b *testing.B) {
					dir := b.TempDir()
					c := config.Default()
					c.Mode = config.ModeBlock
					if err := config.Save(dir+"/config.json", c); err != nil {
						b.Fatal(err)
					}
					s, err := New(Options{DataDir: dir, Build: func(config.Config) (engine.Engine, error) { return &fakeEngine{}, nil }})
					if err != nil {
						b.Fatal(err)
					}
					defer s.Close()
					h := s.IPCHandler()
					var srv *httptest.Server
					var client *http.Client
					if network {
						srv = httptest.NewServer(h)
						defer srv.Close()
						client = srv.Client()
					}
					b.ReportAllocs()
					b.ResetTimer()
					for b.Loop() {
						if network {
							resp, err := client.Post(srv.URL+"/inspect", "application/json", bytes.NewReader(raw))
							if err != nil {
								b.Fatal(err)
							}
							io.Copy(io.Discard, resp.Body)
							resp.Body.Close()
							if resp.StatusCode != 200 {
								b.Fatal(resp.StatusCode)
							}
						} else {
							req := httptest.NewRequest("POST", "http://127.0.0.1/inspect", bytes.NewReader(raw))
							w := httptest.NewRecorder()
							h.ServeHTTP(w, req)
							if w.Code != 200 {
								b.Fatal(w.Code)
							}
						}
					}
				})
			}
		})
	}
}
