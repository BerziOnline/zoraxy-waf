package coraza

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

var headerTraversalSink int

// Measure ONLY the proposed header-enumeration saving, not CRS execution.
// Production keeps its deterministic order unless full engine cost warrants
// a behavioral identity study; iteration order can affect ordered match detail.
func BenchmarkHeaderTraversal(b *testing.B) {
	for _, n := range []int{4, 8, 32, 64} {
		headers := map[string][]string{"Host": {"shop.example"}}
		for i := 0; i < n; i++ {
			headers[fmt.Sprintf("X-Header-%03d", i)] = []string{"value"}
		}
		for _, order := range []string{"sorted", "map"} {
			b.Run(fmt.Sprintf("%d/%s", n, order), func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					total := 0
					if order == "sorted" {
						keys := make([]string, 0, len(headers))
						for k := range headers {
							if !strings.EqualFold(k, "Host") {
								keys = append(keys, k)
							}
						}
						sort.Strings(keys)
						for _, k := range keys {
							for _, v := range headers[k] {
								total += len(k) + len(v)
							}
						}
					} else {
						for k, values := range headers {
							if !strings.EqualFold(k, "Host") {
								for _, v := range values {
									total += len(k) + len(v)
								}
							}
						}
					}
					headerTraversalSink = total
				}
			})
		}
	}
}
