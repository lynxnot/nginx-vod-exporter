################ Build & Dev ################
# Build stage will be used:
# - for building the application for production
# - as target for development (see devspace.yaml)
FROM golang:1.14.1-alpine as build

# Create project directory (workdir)
WORKDIR /app

# Add source code files to WORKDIR
ADD . .

# Build application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-extldflags "-static"' -o nginx_vod_exporter .

# Container start command for development
# Allows DevSpace to restart the dev container
# It is also possible to override this in devspace.yaml via images.*.cmd
CMD [ "go", "run", "nginx_vod_exporter.go" ]


################ Production ################
# Creates a minimal image for production using distroless base image
# More info here: https://github.com/GoogleContainerTools/distroless
FROM gcr.io/distroless/base-debian10 as production


# Copy application binary from build/dev stage to the distroless container
COPY --from=build /app/nginx_vod_exporter /

# Available configuration variables and default values
ENV VOD_EXPORTER_LISTEN_ADDRESS=":19101" \
    VOD_EXPORTER_METRICS_ENDPOINT="/metrics" \
    VOD_EXPORTER_METRICS_NAMESPACE="nginx_vod" \
    VOD_EXPORTER_METRICS_GO="true" \
    VOD_EXPORTER_STATUS_URI="http://localhost/vod-status" \
    VOD_EXPORTER_STATUS_TIMEOUT="2" \
    VOD_EXPORTER_TLS_INSECURE="true"


# Application port (optional)
#EXPOSE 19101

# Container start command for production
ENTRYPOINT [ "/nginx_vod_exporter" ]
