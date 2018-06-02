package exporter

import (
	"context"
	"net/http"
	"time"

	api "github.com/osrg/gobgp/api"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
)

const (
	namespace = "gobgp"
)

var (
	up = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "up"),
		"Is gobgpd gRPC is available.",
		nil, nil,
	)
)

type Exporter struct {
	target string
}

func NewExporter(target string) *Exporter {
	if target == "" {
		target = ":50051"
	}
	return &Exporter{target: target}
}

func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	mCh := make(chan prometheus.Metric)
	done := make(chan struct{})

	go func() {
		for m := range mCh {
			ch <- m.Desc()
		}
		close(done)
	}()

	e.Collect(mCh)
	close(mCh)
	<-done
}

func newDesc(subsystem, name, help string) *prometheus.Desc {
	return prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, name),
		help, nil, nil,
	)
}

func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	opts := []grpc.DialOption{grpc.WithTimeout(time.Second), grpc.WithBlock(), grpc.WithInsecure()}
	ctx := context.Background()
	conn, err := grpc.DialContext(ctx, e.target, opts...)
	if err != nil {
		ch <- prometheus.MustNewConstMetric(
			up, prometheus.GaugeValue, 0,
		)
		return
	}

	ch <- prometheus.MustNewConstMetric(
		up, prometheus.GaugeValue, 1,
	)
	c := api.NewGobgpApiClient(conn)
	if rsp, err := c.GetNeighbor(ctx, &api.GetNeighborRequest{}); err != nil {
		return
	} else {
		for _, p := range rsp.Peers {
			d := newDesc(p.Conf.NeighborAddress, "received", "the number of received routes.")
			ch <- prometheus.MustNewConstMetric(
				d, prometheus.GaugeValue, float64(p.Info.Received),
			)
		}
	}
}

func (e *Exporter) Serve() {
	prometheus.MustRegister(e)

	http.Handle("/metrics", prometheus.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
             <head><title>GoBGP Exporter</title></head>
             <body>
             <h1>GoBGP Exporter</h1>
             <p><a href='` + "/metrics" + `'>Metrics</a></p>
             </body>
             </html>`))
	})
	http.ListenAndServe(":9150", nil)
}
