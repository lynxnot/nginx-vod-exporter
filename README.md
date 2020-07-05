# nginx-vod-exporter

A [prometheus][1] exporter for Kaltura [nginx-vod-module][2].

## Foreword

- Higly inspired by (read copied from) [nginx_vts_exporter][3] and [haproxy_exporter][4]
- This project was the perfect opportunity for me to learn Go, Prometheus and [devspace.sh][5].
- WIP!

## TODO

- implement performance_counters _à la prometheus_
- understand promu & version stuff
- write some tests
- dockerize



[1]: https://github.com/prometheus/prometheus
[2]: https://github.com/kaltura/nginx-vod-module
[3]: https://github.com/hnlq715/nginx-vts-exporter
[4]: https://github.com/prometheus/haproxy_exporter
[5]: https://devspace.sh