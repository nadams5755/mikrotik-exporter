package collector

import (
	"mikrotik-exporter/config"

	"github.com/prometheus/client_golang/prometheus"
	routeros "github.com/go-routeros/routeros/v3"
)

type collectorContext struct {
	ch     chan<- prometheus.Metric
	device *config.Device
	client *routeros.Client
}
