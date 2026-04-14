FROM alpine:3.23@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659 AS core
RUN apk add --no-cache wget tar unzip

WORKDIR /app
ARG VERSION=0.20.2
ARG PLATFORM=Linux_x86_64  # Change this based on your target system

RUN wget https://github.com/privateerproj/privateer/releases/download/v${VERSION}/privateer_${PLATFORM}.tar.gz
RUN tar -xzf privateer_${PLATFORM}.tar.gz

FROM golang:1.26.2-alpine3.22@sha256:c259ff7ffa06f1fd161a6abfa026573cf00f64cfd959c6d2a9d43e3ff63e8729 AS plugin
RUN apk add --no-cache make git
WORKDIR /plugin
COPY . .
RUN make binary

FROM golang:1.26.2-alpine3.22@sha256:c259ff7ffa06f1fd161a6abfa026573cf00f64cfd959c6d2a9d43e3ff63e8729
RUN addgroup -g 1001 -S appgroup && adduser -u 1001 -S appuser -G appgroup

RUN mkdir -p /.privateer/bin && chown -R appuser:appgroup /.privateer
WORKDIR /.privateer/bin
USER appuser

COPY --from=core /app/pvtr .
COPY --from=plugin /plugin/github-repo .
COPY --from=plugin /plugin/container-entrypoint.sh .

# The config file must be provided at run time.
# example: docker run -v /path/to/config.yml:/.privateer/config.yml privateer-image
CMD ["./container-entrypoint.sh"]
