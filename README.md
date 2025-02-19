# nginx-vod-exporter

A [prometheus][1] exporter for Kaltura [nginx-vod-module][2].
Higly inspired by [nginx_vts_exporter][3] and [haproxy_exporter][4]

## Usage

The docker image is available on docker hub:

```bash
$ docker pull lynxnot/nginx-vod-exporter

$ docker run lynxnot/nginx-vod-exporter -help
Usage of /nginx_vod_exporter:
  -exporter.address string
        Exporter listen address (default ":19101")
  -metrics.endpoint string
        Path under which to expose metrics (default "/metrics")
  -metrics.namespace string
        Prometheus metrics namespace (default "nginx_vod")
  -metrics.process
        Export process and go metrics. (default true)
  -status.timeout int
        Seconds to wait for a response from vod-status (default 2)
  -status.uri string
        URI to nginx-vod status page (default "http://localhost/vod-status")
  -tls.insecure
        Do not verify SSL certificates (default true)
  -version
        Show version and exit
```

The following environment variables allow to configure the exporter. The values are the default.
```
VOD_EXPORTER_LISTEN_ADDRESS=":19101"
VOD_EXPORTER_METRICS_ENDPOINT="/metrics"
VOD_EXPORTER_METRICS_NAMESPACE="nginx_vod"
VOD_EXPORTER_METRICS_GO="true"
VOD_EXPORTER_STATUS_URI="http://localhost/vod-status"
VOD_EXPORTER_STATUS_TIMEOUT="2"
VOD_EXPORTER_TLS_INSECURE="true
```

These variables are overriding the default options. 
Arguments specified on the command line will supersede defaults.


## Build

The build supports multi-arch builds using [docker buildx][6].

```
$ docker buildx build --push --platform linux/amd64,linux/arm64 -t lynxnot/nginx-vod-exporter:<TAG> .
```


## TODO

- add grafana dashboard
- better versioning/release workflow
- write some tests


[1]: https://github.com/prometheus/prometheus
[2]: https://github.com/kaltura/nginx-vod-module
[3]: https://github.com/hnlq715/nginx-vts-exporter
[4]: https://github.com/prometheus/haproxy_exporter
[5]: https://devspace.sh
[6]: https://docs.docker.com/build/building/multi-platform/