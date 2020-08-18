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
	"strconv"
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

func newPerfMetric(metricName string, docString string, t prometheus.ValueType, constLabels prometheus.Labels) metricInfo {
	return metricInfo{
		Desc: prometheus.NewDesc(
			prometheus.BuildFQName(*metricsNamespace, "perf", metricName),
			docString,
			[]string{"op"}, // metadata or mapping
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
		"fetch_hit":     newCacheMetric("fetch_total", "Total fetches", prometheus.CounterValue, prometheus.Labels{"result": "hit"}),
		"fetch_miss":    newCacheMetric("fetch_total", "Total fetches", prometheus.CounterValue, prometheus.Labels{"result": "miss"}),
		"evicted":       newCacheMetric("evicted_total", "Total evictions", prometheus.CounterValue, nil),
		"store_bytes":   newCacheMetric("bytes", "Total bytes", prometheus.CounterValue, prometheus.Labels{"op": "store"}),
		"fetch_bytes":   newCacheMetric("bytes", "Total bytes", prometheus.CounterValue, prometheus.Labels{"op": "fetch"}),
		"evicted_bytes": newCacheMetric("bytes", "Total bytes", prometheus.CounterValue, prometheus.Labels{"op": "evict"}),
		"reset":         newCacheMetric("reset_total", "Total numbers of counter resets", prometheus.CounterValue, nil),
		"entries":       newCacheMetric("entries", "Current number of entries", prometheus.GaugeValue, nil),
		"data_size":     newCacheMetric("used_bytes", "Current bytes in cache", prometheus.GaugeValue, nil),
	}

	perfMetrics = metrics{
		"time_usec":         newPerfMetric("time_usec", "Total op time", prometheus.CounterValue, nil),
		"total":             newPerfMetric("total", "Total ops", prometheus.CounterValue, nil),
		// maxTime may need a gauge val, as noted here:
		// https://github.com/kaltura/nginx-vod-module/blob/5a69308166afcfe1669aabf399920bfa25dfd82f/ngx_perf_counters.h#L43
		"maxtime_usec":      newPerfMetric("maxtime_usec", "Max op time", prometheus.CounterValue, nil),
		"maxtime_timestamp": newPerfMetric("maxtime_timestamp", "Max op time timestamp", prometheus.CounterValue, nil),
		"maxtime_pid":       newPerfMetric("maxtime_pid", "Max op time PID", prometheus.GaugeValue, nil),
	}
)

// Exporter collects Kaltura VOD stats from the given URI and exports them
// in prometheus metrics format.
type Exporter struct {
	URI   string
	mutex sync.RWMutex

	infoMetric   *prometheus.Desc
	cacheMetrics metrics
	perfMetrics  metrics
}

// NewExporter returns an initialized exporter
func NewExporter(uri string) *Exporter {
	return &Exporter{
		URI: uri,
		infoMetric: prometheus.NewDesc(
			prometheus.BuildFQName(*metricsNamespace, "module", "info"),
			"kaltura/nginx-vod-module info", []string{"version"}, nil),

		cacheMetrics: cacheMetrics,
		perfMetrics:  perfMetrics,
	}
}

// Describe describes all metrics exported, implements prometheus.Collector
func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- e.infoMetric

	for _, m := range e.cacheMetrics {
		ch <- m.Desc
	}

	for _, m := range e.perfMetrics {
		ch <- m.Desc
	}
}

func mustNewConstMetric(mi metricInfo, value uint64, labelValues ...string) prometheus.Metric {
	return prometheus.MustNewConstMetric(mi.Desc, mi.Type, float64(value), labelValues...)
}

type (
	metricValues map[string]map[string]uint64

	vodStatusValues struct {
		version     string
		cacheValues metricValues
		perfValues  metricValues
	}
)

func fetchStatusValues(uri string) (*vodStatusValues, error) {

	vodStatus, err := fetchAndUnmarshal(uri)
	if err != nil {
		return nil, err
	}
	values := &vodStatusValues{
		version: vodStatus.Version,
		cacheValues: metricValues{
			"metadata": {
				"store_ok":      vodStatus.MetadataCache.StoreOK,
				"store_err":     vodStatus.MetadataCache.StoreErr,
				"store_exists":  vodStatus.MetadataCache.StoreExists,
				"store_bytes":   vodStatus.MetadataCache.StoreBytes,
				"fetch_hit":     vodStatus.MetadataCache.FetchHit,
				"fetch_miss":    vodStatus.MetadataCache.FetchMiss,
				"fetch_bytes":   vodStatus.MetadataCache.FetchBytes,
				"evicted":       vodStatus.MetadataCache.Evicted,
				"evicted_bytes": vodStatus.MetadataCache.EvictedBytes,
				"reset":         vodStatus.MetadataCache.Reset,
				"entries":       vodStatus.MetadataCache.Entries,
				"data_size":     vodStatus.MetadataCache.DataSize,
			},
			"mapping": {
				"store_ok":      vodStatus.MappingCache.StoreOK,
				"store_err":     vodStatus.MappingCache.StoreErr,
				"store_exists":  vodStatus.MappingCache.StoreExists,
				"store_bytes":   vodStatus.MappingCache.StoreBytes,
				"fetch_hit":     vodStatus.MappingCache.FetchHit,
				"fetch_miss":    vodStatus.MappingCache.FetchMiss,
				"fetch_bytes":   vodStatus.MappingCache.FetchBytes,
				"evicted":       vodStatus.MappingCache.Evicted,
				"evicted_bytes": vodStatus.MappingCache.EvictedBytes,
				"reset":         vodStatus.MappingCache.Reset,
				"entries":       vodStatus.MappingCache.Entries,
				"data_size":     vodStatus.MappingCache.DataSize,
			},
		},
		perfValues: metricValues{
			"fetch_cache": {
				"time_usec":         vodStatus.PerformanceCounters.FetchCache.Sum,
				"total":             vodStatus.PerformanceCounters.FetchCache.Count,
				"maxtime_usec":      vodStatus.PerformanceCounters.FetchCache.Max,
				"maxtime_timestamp": vodStatus.PerformanceCounters.FetchCache.MaxTime,
				"maxtime_pid":       vodStatus.PerformanceCounters.FetchCache.MaxPid,
			},
			"store_cache": {
				"time_usec":         vodStatus.PerformanceCounters.StoreCache.Sum,
				"total":             vodStatus.PerformanceCounters.StoreCache.Count,
				"maxtime_usec":      vodStatus.PerformanceCounters.StoreCache.Max,
				"maxtime_timestamp": vodStatus.PerformanceCounters.StoreCache.MaxTime,
				"maxtime_pid":       vodStatus.PerformanceCounters.StoreCache.MaxPid,
			},
			"map_path": {
				"time_usec":         vodStatus.PerformanceCounters.MapPath.Sum,
				"total":             vodStatus.PerformanceCounters.MapPath.Count,
				"maxtime_usec":      vodStatus.PerformanceCounters.MapPath.Max,
				"maxtime_timestamp": vodStatus.PerformanceCounters.MapPath.MaxTime,
				"maxtime_pid":       vodStatus.PerformanceCounters.MapPath.MaxPid,
			},
			"parse_media_set": {
				"time_usec":         vodStatus.PerformanceCounters.ParseMediaSet.Sum,
				"total":             vodStatus.PerformanceCounters.ParseMediaSet.Count,
				"maxtime_usec":      vodStatus.PerformanceCounters.ParseMediaSet.Max,
				"maxtime_timestamp": vodStatus.PerformanceCounters.ParseMediaSet.MaxTime,
				"maxtime_pid":       vodStatus.PerformanceCounters.ParseMediaSet.MaxPid,
			},
			"get_drm_info": {
				"time_usec":         vodStatus.PerformanceCounters.GetDrmInfo.Sum,
				"total":             vodStatus.PerformanceCounters.GetDrmInfo.Count,
				"maxtime_usec":      vodStatus.PerformanceCounters.GetDrmInfo.Max,
				"maxtime_timestamp": vodStatus.PerformanceCounters.GetDrmInfo.MaxTime,
				"maxtime_pid":       vodStatus.PerformanceCounters.GetDrmInfo.MaxPid,
			},
			"open_file": {
				"time_usec":         vodStatus.PerformanceCounters.OpenFile.Sum,
				"total":             vodStatus.PerformanceCounters.OpenFile.Count,
				"maxtime_usec":      vodStatus.PerformanceCounters.OpenFile.Max,
				"maxtime_timestamp": vodStatus.PerformanceCounters.OpenFile.MaxTime,
				"maxtime_pid":       vodStatus.PerformanceCounters.OpenFile.MaxPid,
			},
			"async_open_file": {
				"time_usec":         vodStatus.PerformanceCounters.AsyncOpenFile.Sum,
				"total":             vodStatus.PerformanceCounters.AsyncOpenFile.Count,
				"maxtime_usec":      vodStatus.PerformanceCounters.AsyncOpenFile.Max,
				"maxtime_timestamp": vodStatus.PerformanceCounters.AsyncOpenFile.MaxTime,
				"maxtime_pid":       vodStatus.PerformanceCounters.AsyncOpenFile.MaxPid,
			},
			"read_file": {
				"time_usec":         vodStatus.PerformanceCounters.ReadFile.Sum,
				"total":             vodStatus.PerformanceCounters.ReadFile.Count,
				"maxtime_usec":      vodStatus.PerformanceCounters.ReadFile.Max,
				"maxtime_timestamp": vodStatus.PerformanceCounters.ReadFile.MaxTime,
				"maxtime_pid":       vodStatus.PerformanceCounters.ReadFile.MaxPid,
			},
			"async_read_file": {
				"time_usec":         vodStatus.PerformanceCounters.AsyncReadFile.Sum,
				"total":             vodStatus.PerformanceCounters.AsyncReadFile.Count,
				"maxtime_usec":      vodStatus.PerformanceCounters.AsyncReadFile.Max,
				"maxtime_timestamp": vodStatus.PerformanceCounters.AsyncReadFile.MaxTime,
				"maxtime_pid":       vodStatus.PerformanceCounters.AsyncReadFile.MaxPid,
			},
			"media_parse": {
				"time_usec":         vodStatus.PerformanceCounters.MediaParse.Sum,
				"total":             vodStatus.PerformanceCounters.MediaParse.Count,
				"maxtime_usec":      vodStatus.PerformanceCounters.MediaParse.Max,
				"maxtime_timestamp": vodStatus.PerformanceCounters.MediaParse.MaxTime,
				"maxtime_pid":       vodStatus.PerformanceCounters.MediaParse.MaxPid,
			},
			"build_manifest": {
				"time_usec":         vodStatus.PerformanceCounters.BuildManifest.Sum,
				"total":             vodStatus.PerformanceCounters.BuildManifest.Count,
				"maxtime_usec":      vodStatus.PerformanceCounters.BuildManifest.Max,
				"maxtime_timestamp": vodStatus.PerformanceCounters.BuildManifest.MaxTime,
				"maxtime_pid":       vodStatus.PerformanceCounters.BuildManifest.MaxPid,
			},
			"init_frame_processing": {
				"time_usec":         vodStatus.PerformanceCounters.InitFrameProcessing.Sum,
				"total":             vodStatus.PerformanceCounters.InitFrameProcessing.Count,
				"maxtime_usec":      vodStatus.PerformanceCounters.InitFrameProcessing.Max,
				"maxtime_timestamp": vodStatus.PerformanceCounters.InitFrameProcessing.MaxTime,
				"maxtime_pid":       vodStatus.PerformanceCounters.InitFrameProcessing.MaxPid,
			},
			"process_frames": {
				"time_usec":         vodStatus.PerformanceCounters.ProcessFrames.Sum,
				"total":             vodStatus.PerformanceCounters.ProcessFrames.Count,
				"maxtime_usec":      vodStatus.PerformanceCounters.ProcessFrames.Max,
				"maxtime_timestamp": vodStatus.PerformanceCounters.ProcessFrames.MaxTime,
				"maxtime_pid":       vodStatus.PerformanceCounters.ProcessFrames.MaxPid,
			},
			// Total should be the sum of every op ?
			//"total": {
			//	"time_usec":         vodStatus.PerformanceCounters.Total.Sum,
			//	"total":             vodStatus.PerformanceCounters.Total.Count,
			//	"maxtime_usec":      vodStatus.PerformanceCounters.Total.Max,
			//	"maxtime_timestamp": vodStatus.PerformanceCounters.Total.MaxTime,
			//	"maxtime_pid":       vodStatus.PerformanceCounters.Total.MaxPid,
			//},
		},
	}

	return values, nil
}

// Collect fetches stats from upstream and delivers them as metrics
// Implents prometheus.Collector
func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	e.mutex.Lock() // Protect metrics from concurrent collects
	defer e.mutex.Unlock()

	statusValues, err := fetchStatusValues(e.URI)
	if err != nil {
		// errors are logged in fetchAndUnmarshal
		return
	}

	// Cache Metrics
	for region, values := range statusValues.cacheValues {
		for name, metric := range e.cacheMetrics {
			ch <- mustNewConstMetric(metric, values[name], region)
		}
	}

	// Perf Metrics
	for op, values := range statusValues.perfValues {
		for name, metric := range e.perfMetrics {
			ch <- mustNewConstMetric(metric, values[name], op)
		}
	}

	// infoMetric uses labels to expose data, the GaugeValue is constant
	ch <- prometheus.MustNewConstMetric(e.infoMetric, prometheus.GaugeValue, float64(1), statusValues.version)
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

func lookupEnvOrString(envVar string, defaultValue string) string {
	if v, ok := os.LookupEnv(envVar); ok {
		return v
	}
	return defaultValue
}

func lookupEnvOrBool(envVar string, defaultValue bool) bool {
	if v, ok := os.LookupEnv(envVar); ok {
		b, err := strconv.ParseBool(v)
		if err != nil {
			log.Fatalf("lookupEnvOrBool(%s): %v", envVar, err)
		}
		return b
	}
	return defaultValue
}

func lookupEnvOrInt(envVar string, defaultValue int) int {
	if v, ok := os.LookupEnv(envVar); ok {
		i, err := strconv.Atoi(v)
		if err != nil {
			log.Fatalf("lookupEnvOrInt(%s): %v", envVar, err)
		}
		return i
	}
	return defaultValue
}

var (
	listenAddress    = flag.String("exporter.address", lookupEnvOrString("VOD_EXPORTER_LISTEN_ADDRESS", ":19101"), "Exporter listen address")
	metricsEndpoint  = flag.String("metrics.endpoint", lookupEnvOrString("VOD_EXPORTER_METRICS_ENDPOINT", "/metrics"), "Path under which to expose metrics")
	metricsNamespace = flag.String("metrics.namespace", lookupEnvOrString("VOD_EXPORTER_METRICS_NAMESPACE", defaultNameSpace), "Prometheus metrics namespace")
	metricsGo        = flag.Bool("metrics.process", lookupEnvOrBool("VOD_EXPORTER_METRICS_GO", true), "Export process and go metrics.")
	vodStatusURI     = flag.String("status.uri", lookupEnvOrString("VOD_EXPORTER_STATUS_URI", "http://localhost/vod-status"), "URI to nginx-vod status page")
	vodStatusTimeout = flag.Int("status.timeout", lookupEnvOrInt("VOD_EXPORTER_STATUS_TIMEOUT", 2), "Seconds to wait for a response from vod-status")
	insecureSSL      = flag.Bool("tls.insecure", lookupEnvOrBool("VOD_EXPORTER_TLS_INSECURE", true), "Do not verify SSL certificates")
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
