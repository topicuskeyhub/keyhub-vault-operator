package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	KeyHubApiRequests = createKeyHubApiRequestTotal()
)

func init() {
	// Register custom metrics with the global prometheus registry
	metrics.Registry.MustRegister(KeyHubApiRequests)
}

func createKeyHubApiRequestTotal() *prometheus.CounterVec {
	return prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "keyhub",
			Subsystem: "api",
			Name:      "request_total",
			Help:      "Number of KeyHub API requests",
		},
		[]string{"resource", "verb"},
	)
}

// Reset all metrics during tests
func Reset() {
	KeyHubApiRequests.Reset()
}
