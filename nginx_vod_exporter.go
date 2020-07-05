package main

import (
	"crypto/tls"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	progName string = "nginx-vod-exporter"
	// use a const for now...
	progVersion string = "0.1.0"
	// defaultNameSpace for prometheus metrics
	defaultNameSpace string = "nginx_vod"
)

// MetadataCache  metadata_cache
type MetadataCache struct {
	XMLName      xml.Name `xml:"metadata_cache"`
	StoreOK      uint64   `xml:"store_ok"`
	StoreBytes   uint64   `xml:"store_bytes"`
	StoreErr     uint64   `xml:"store_err"`
	StoreExists  uint64   `xml:"store_exists"`
	FetchHit     uint64   `xml:"fetch_hit"`
	FetchBytes   uint64   `xml:"fetch_bytes"`
	FetchMiss    uint64   `xml:"fetch_miss"`
	Evicted      uint64   `xml:"evicted"`
	EvictedBytes uint64   `xml:"evicted_bytes"`
	Reset        uint64   `xml:"reset"`
	Entries      uint64   `xml:"entries"`
	DataSize     uint64   `xml:"data_size"`
}

// MappingCache  mapping_cache
type MappingCache struct {
	XMLName xml.Name `xml:"mapping_cache"`
}

// PerformanceCounters  performance_counters
type PerformanceCounters struct {
	XMLName xml.Name `xml:"performance_counters"`
}

// VodStatus  represent the vod-status xml
type VodStatus struct {
	XMLName       xml.Name `xml:"vod"`
	Version       string   `xml:"version"`
	MetadataCache MetadataCache
	//MappingCache MappingCache
	//PerformanceCounters PerformanceCounters
}

// Exporter collects Kaltura VOD stats from the given URI and exports them
// in prometheus metrics format.
type Exporter struct {
	URI        string
	infoMetric *prometheus.Desc
}

// NewExporter returns an initialized exporter
func NewExporter(uri string) *Exporter {
	return &Exporter{
		URI: uri,
		infoMetric: prometheus.NewDesc(
			prometheus.BuildFQName(*metricsNamespace, "info", "version"),
			"kaltura/nginx-vod-module info", []string{"version"}, nil),
	}
}

// Describe describes all metrics exported, implements prometheus.Collector
func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- e.infoMetric
}

// Collect fetches stats from upstream and delivers them as metrics
// Implents prometheus.Collector
func (e *Exporter) Collect(ch chan<- prometheus.Metric) {

	vodStatus, err := fetchAndUnmarshal(e.URI)
	if err != nil {
		// errors are logged in fetchAndUnmarshal
		return
	}

	// infoMatric uses labels to expose data, the GaugeValue is constant
	ch <- prometheus.MustNewConstMetric(e.infoMetric, prometheus.GaugeValue, float64(1), vodStatus.Version)
}

// fetch and parse xml response
func fetchAndUnmarshal(uri string) (*VodStatus, error) {

	body, err := fetchHTTP(uri, *insecureSSL, time.Duration(*vodStatusTimeout)*time.Second)()
	if err != nil {
		log.Println("fetchHTTP failed:", err)
		return nil, err
	}
	defer body.Close()

	data, err := ioutil.ReadAll(body)
	if err != nil {
		log.Println("ioutil.ReadAll failed:", err)
		return nil, err
	}

	vodStatus := &VodStatus{}
	err = xml.Unmarshal(data, vodStatus)
	if err != nil {
		log.Println("xml.Unmarshal failed:", err)
		return nil, err
	}

	return vodStatus, nil
}

// Copied from haproxy_exporter
func fetchHTTP(uri string, sslVerify bool, timeout time.Duration) func() (io.ReadCloser, error) {
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: !sslVerify}}
	client := http.Client{
		Timeout:   timeout,
		Transport: tr,
	}

	return func() (io.ReadCloser, error) {
		resp, err := client.Get(uri)
		if err != nil {
			return nil, err
		}
		if !(resp.StatusCode >= 200 && resp.StatusCode < 300) {
			resp.Body.Close()
			return nil, fmt.Errorf("HTTP status %d", resp.StatusCode)
		}
		return resp.Body, nil
	}
}

var (
	listenAddress    = flag.String("exporter.address", ":19101", "Exporter listen address")
	metricsEndpoint  = flag.String("metrics.endpoint", "/metrics", "Path under which to expose metrics")
	metricsNamespace = flag.String("metrics.namespace", "nginx_vod", "Prometheus metrics namespace")
	metricsGo        = flag.Bool("metrics.process", true, "Export process and go metrics.")
	vodStatusURI     = flag.String("status.uri", "http://localhost/vod-status", "URI to nginx-vod status page")
	vodStatusTimeout = flag.Int("status.timeout", 2, "Seconds to wait for a response from vod-status")
	insecureSSL      = flag.Bool("tls.insecure", true, "Do not verify SSL certificates")
	showVersion      = flag.Bool("version", false, "Show version and exit")
)

func main() {
	flag.Parse()

	if *showVersion {
		fmt.Printf("%s %s\n", progName, progVersion)
		os.Exit(0)
	}

	log.Printf("Starting %s %s", progName, progVersion)

	exporter := NewExporter(*vodStatusURI)
	prometheus.MustRegister(exporter)

	if !(*metricsGo) {
		prometheus.Unregister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{
			PidFn: func() (int, error) {
				return os.Getpid(), nil
			},
		}))
		prometheus.Unregister(prometheus.NewGoCollector())
	}

	http.Handle(*metricsEndpoint, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><head><title>NginX Kaltura VOD Exporter</title></head>
		    <body><h1>NginX Kaltura VOD Exporter</h1>
		    <p><a href="` + *metricsEndpoint + `">Metrics</a></p>
		    </body>
			</html>`))
	})

	log.Printf("Starting Server at : %s", *listenAddress)
	log.Printf("Metrics endpoint: %s", *metricsEndpoint)
	log.Printf("Metrics namespace: %s", *metricsNamespace)
	log.Printf("Scraping information from : %s", *vodStatusURI)
	log.Fatal(http.ListenAndServe(*listenAddress, nil))
}
