package docker

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

var (
	dockerLayersScanned = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "docker_layers_scanned",
		Help:      "Total number of Docker layers scanned.",
	},
		[]string{"source_name"})

	dockerImageConfigsScanned = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "docker_image_configs_scanned",
		Help:      "Total number of Docker image config metadata entries scanned.",
	},
		[]string{"source_name"})

	dockerImagesScanned = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "docker_images_scanned",
		Help:      "Total number of Docker images scanned.",
	},
		[]string{"source_name"})
)
