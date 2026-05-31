package collector

import (
	"mikrotik-exporter/config"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
)

const conntrackSentence = "/ip/firewall/connection/tracking/print @ [{`.proplist` `total-entries,max-entries,total-ip4-entries,total-ip6-entries`}]"

func newConntrackTestSetup(t *testing.T, fields ...string) (*collectorContext, chan prometheus.Metric, func()) {
	c, s := newPair(t)

	go func() {
		defer s.Close()
		s.readSentence(t, conntrackSentence)
		s.writeSentence(t, append([]string{"!re"}, fields...)...)
		s.writeSentence(t, "!done")
	}()

	ch := make(chan prometheus.Metric, 4)
	ctx := &collectorContext{
		ch:     ch,
		device: &config.Device{Name: "test", Address: "192.0.2.1"},
		client: c,
	}
	return ctx, ch, func() { c.Close() }
}

// TestConntrackV7 verifies all four metrics are emitted when the router
// returns the IPv4/IPv6 breakdown fields introduced in RouterOS v7.
func TestConntrackV7(t *testing.T) {
	ctx, ch, cleanup := newConntrackTestSetup(t,
		"=total-entries=100",
		"=max-entries=200000",
		"=total-ip4-entries=95",
		"=total-ip6-entries=5",
	)
	defer cleanup()

	assert.NoError(t, newConntrackCollector().collect(ctx))
	close(ch)

	var count int
	for range ch {
		count++
	}
	assert.Equal(t, 4, count, "expected 4 metrics on RouterOS v7 response")
}

// TestConntrackV6Compat verifies the collector still works when the router
// omits total-ip4-entries and total-ip6-entries (RouterOS v6 and earlier).
func TestConntrackV6Compat(t *testing.T) {
	ctx, ch, cleanup := newConntrackTestSetup(t,
		"=total-entries=80",
		"=max-entries=200000",
	)
	defer cleanup()

	assert.NoError(t, newConntrackCollector().collect(ctx))
	close(ch)

	var count int
	for range ch {
		count++
	}
	assert.Equal(t, 2, count, "expected 2 metrics on RouterOS v6 response (no IPv4/IPv6 breakdown)")
}

func TestConntrackValues(t *testing.T) {
	ctx, ch, cleanup := newConntrackTestSetup(t,
		"=total-entries=100",
		"=max-entries=200000",
		"=total-ip4-entries=95",
		"=total-ip6-entries=5",
	)
	defer cleanup()

	assert.NoError(t, newConntrackCollector().collect(ctx))
	close(ch)

	expected := map[string]float64{
		"mikrotik_conntrack_entries":      100,
		"mikrotik_conntrack_max_entries":  200000,
		"mikrotik_conntrack_ipv4_entries": 95,
		"mikrotik_conntrack_ipv6_entries": 5,
	}

	found := make(map[string]float64)
	for m := range ch {
		var pb dto.Metric
		m.Write(&pb)
		found[m.Desc().String()] = pb.Gauge.GetValue()
	}

	for fqName, wantVal := range expected {
		var matched bool
		for descStr, gotVal := range found {
			if containsSubstring(descStr, fqName) {
				assert.Equal(t, wantVal, gotVal, "wrong value for %s", fqName)
				matched = true
				break
			}
		}
		assert.True(t, matched, "metric %s not found in output", fqName)
	}
}

func containsSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
