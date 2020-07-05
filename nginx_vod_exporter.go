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
	"sync"
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

// CacheCounters represent
type CacheCounters struct {
	StoreOK      uint64 `xml:"store_ok"`
	StoreBytes   uint64 `xml:"store_bytes"`
	StoreErr     uint64 `xml:"store_err"`
	StoreExists  uint64 `xml:"store_exists"`
	FetchHit     uint64 `xml:"fetch_hit"`
	FetchBytes   uint64 `xml:"fetch_bytes"`
	FetchMiss    uint64 `xml:"fetch_miss"`
	Evicted      uint64 `xml:"evicted"`
	EvictedBytes uint64 `xml:"evicted_bytes"`
	Reset        uint64 `xml:"reset"`
	Entries      uint64 `xml:"entries"`
	DataSize     uint64 `xml:"data_size"`
}

// OpCounter represent a perfomance counter
type OpCounter struct {
	Sum     uint64 `xml:"sum"`
	Count   uint64 `xml:"count"`
	Max     uint64 `xml:"max"`
	MaxTime uint64 `xml:"max_time"`
	MaxPid  uint64 `xml:"max_pid"`
}

// PerformanceCounters  performance_counters
type PerformanceCounters struct {
	FetchCache          OpCounter `xml:"fetch_cache"`
	StoreCache          OpCounter `xml:"store_cache"`
	MapPath             OpCounter `xml:"map_path"`
	ParseMediaSet       OpCounter `xml:"parse_media_set"`
	GetDrmInfo          OpCounter `xml:"get_drm_info"`
	OpenFile            OpCounter `xml:"open_file"`
	AsyncOpenFile       OpCounter `xml:"async_open_file"`
	ReadFile            OpCounter `xml:"read_file"`
	AsyncReadFile       OpCounter `xml:"async_read_file"`
	MediaParse          OpCounter `xml:"media_parse"`
	BuildManifest       OpCounter `xml:"build_manifest"`
	InitFrameProcessing OpCounter `xml:"init_frame_processing"`
	ProcessFrames       OpCounter `xml:"process_frames"`
	Total               OpCounter `xml:"total"`
}

// VodStatus  represent the vod-status xml
type VodStatus struct {
	XMLName             xml.Name            `xml:"vod"`
	Version             string              `xml:"version"`
	MetadataCache       CacheCounters       `xml:"metadata_cache"`
	MappingCache        CacheCounters       `xml:"mapping_cache"`
	PerformanceCounters PerformanceCounters `xml:"performance_counters"`
}

// keeps Desc and Types togheter
type metricInfo struct {
	Desc *prometheus.Desc
	Type prometheus.ValueType
}

func newCacheMetric(metricName string, docString string, t prometheus.ValueType, constLabels prometheus.Labels) metricInfo {
	return metricInfo{
		Desc: prometheus.NewDesc(
			prometheus.BuildFQName(*metricsNamespace, "cache", metricName),
			docString,
			[]string{"buffer"}, // metadata or mapping
			constLabels,
		),
		Type: t,
	}
}

type metrics map[string]metricInfo

var (
	cacheMetrics = metrics{
		"store_ok":      newCacheMetric("store_total", "Total store ops", prometheus.CounterValue, prometheus.Labels{"result": "ok"}),
		"store_err":     newCacheMetric("store_total", "Total store ops", prometheus.CounterValue, prometheus.Labels{"result": "err"}),
		"store_exists":  newCacheMetric("store_total", "Total store ops", prometheus.CounterValue, prometheus.Labels{"result": "exists"}),
		"store_bytes":   newCacheMetric("store_bytes", "Total bytes stored", prometheus.CounterValue, nil),
		"fetch_hit":     newCacheMetric("fetch_total", "Total fetches", prometheus.CounterValue, prometheus.Labels{"result": "hit"}),
		"fetch_miss":    newCacheMetric("fetch_total", "Total fetches", prometheus.CounterValue, prometheus.Labels{"result": "miss"}),
		"fetch_bytes":   newCacheMetric("fetch_bytes", "Total bytes fetched", prometheus.CounterValue, nil),
		"evicted":       newCacheMetric("evicted_total", "Total evictions", prometheus.CounterValue, nil),
		"evicted_bytes": newCacheMetric("evicted_bytes", "Total bytes evicted", prometheus.CounterValue, nil),
		"reset":         newCacheMetric("reset_total", "Total numbers of counter resets", prometheus.CounterValue, nil),
		"entries":       newCacheMetric("entries", "Current number of entries", prometheus.GaugeValue, nil),
		"data_size":     newCacheMetric("used_bytes", "Current bytes in cache", prometheus.GaugeValue, nil),
	}
)

// Exporter collects Kaltura VOD stats from the given URI and exports them
// in prometheus metrics format.
type Exporter struct {
	URI   string
	mutex sync.RWMutex

	infoMetric   *prometheus.Desc
	cacheMetrics metrics
}

// NewExporter returns an initialized exporter
func NewExporter(uri string) *Exporter {
	return &Exporter{
		URI: uri,
		infoMetric: prometheus.NewDesc(
			prometheus.BuildFQName(*metricsNamespace, "module", "info"),
			"kaltura/nginx-vod-module info", []string{"version"}, nil),

		cacheMetrics: cacheMetrics,
	}
}

// Describe describes all metrics exported, implements prometheus.Collector
func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- e.infoMetric

	for _, m := range e.cacheMetrics {
		ch <- m.Desc
	}
}

func mustNewConstMetric(mi metricInfo, value uint64, labelValues ...string) prometheus.Metric {
	return prometheus.MustNewConstMetric(mi.Desc, mi.Type, float64(value), labelValues...)
}

// Collect fetches stats from upstream and delivers them as metrics
// Implents prometheus.Collector
func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	e.mutex.Lock() // Protect metrics from concurrent collects
	defer e.mutex.Unlock()

	vodStatus, err := fetchAndUnmarshal(e.URI)
	if err != nil {
		// errors are logged in fetchAndUnmarshal
		return
	}

	// MetadataCache
	ch <- mustNewConstMetric(e.cacheMetrics["store_ok"], vodStatus.MetadataCache.StoreOK, "metadata")
	ch <- mustNewConstMetric(e.cacheMetrics["store_err"], vodStatus.MetadataCache.StoreErr, "metadata")
	ch <- mustNewConstMetric(e.cacheMetrics["store_exists"], vodStatus.MetadataCache.StoreExists, "metadata")
	ch <- mustNewConstMetric(e.cacheMetrics["store_bytes"], vodStatus.MetadataCache.StoreBytes, "metadata")
	ch <- mustNewConstMetric(e.cacheMetrics["fetch_hit"], vodStatus.MetadataCache.FetchHit, "metadata")
	ch <- mustNewConstMetric(e.cacheMetrics["fetch_miss"], vodStatus.MetadataCache.FetchMiss, "metadata")
	ch <- mustNewConstMetric(e.cacheMetrics["fetch_bytes"], vodStatus.MetadataCache.FetchBytes, "metadata")
	ch <- mustNewConstMetric(e.cacheMetrics["evicted"], vodStatus.MetadataCache.Evicted, "metadata")
	ch <- mustNewConstMetric(e.cacheMetrics["evicted_bytes"], vodStatus.MetadataCache.EvictedBytes, "metadata")
	ch <- mustNewConstMetric(e.cacheMetrics["reset"], vodStatus.MetadataCache.Reset, "metadata")
	ch <- mustNewConstMetric(e.cacheMetrics["entries"], vodStatus.MetadataCache.Entries, "metadata")
	ch <- mustNewConstMetric(e.cacheMetrics["data_size"], vodStatus.MetadataCache.DataSize, "metadata")

	// MappingCache
	ch <- mustNewConstMetric(e.cacheMetrics["store_ok"], vodStatus.MappingCache.StoreOK, "mapping")
	ch <- mustNewConstMetric(e.cacheMetrics["store_err"], vodStatus.MappingCache.StoreErr, "mapping")
	ch <- mustNewConstMetric(e.cacheMetrics["store_exists"], vodStatus.MappingCache.StoreExists, "mapping")
	ch <- mustNewConstMetric(e.cacheMetrics["store_bytes"], vodStatus.MappingCache.StoreBytes, "mapping")
	ch <- mustNewConstMetric(e.cacheMetrics["fetch_hit"], vodStatus.MappingCache.FetchHit, "mapping")
	ch <- mustNewConstMetric(e.cacheMetrics["fetch_miss"], vodStatus.MappingCache.FetchMiss, "mapping")
	ch <- mustNewConstMetric(e.cacheMetrics["fetch_bytes"], vodStatus.MappingCache.FetchBytes, "mapping")
	ch <- mustNewConstMetric(e.cacheMetrics["evicted"], vodStatus.MappingCache.Evicted, "mapping")
	ch <- mustNewConstMetric(e.cacheMetrics["evicted_bytes"], vodStatus.MappingCache.EvictedBytes, "mapping")
	ch <- mustNewConstMetric(e.cacheMetrics["reset"], vodStatus.MappingCache.Reset, "mapping")
	ch <- mustNewConstMetric(e.cacheMetrics["entries"], vodStatus.MappingCache.Entries, "mapping")
	ch <- mustNewConstMetric(e.cacheMetrics["data_size"], vodStatus.MappingCache.DataSize, "mapping")

	// infoMetric uses labels to expose data, the GaugeValue is constant
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
	metricsNamespace = flag.String("metrics.namespace", defaultNameSpace, "Prometheus metrics namespace")
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
