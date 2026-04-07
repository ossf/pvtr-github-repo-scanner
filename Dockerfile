FROM alpine:3.23@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659 AS core
RUN apk add --no-cache wget tar unzip

WORKDIR /app
ARG VERSION=0.15.0
ARG PLATFORM=Linux_x86_64  # Change this based on your target system

RUN wget https://github.com/privateerproj/privateer/releases/download/v${VERSION}/privateer_${PLATFORM}.tar.gz
RUN tar -xzf privateer_${PLATFORM}.tar.gz

FROM golang:1.26.1-alpine3.22@sha256:07e91d24f6330432729082bb580983181809e0a48f0f38ecde26868d4568c6ac AS plugin
RUN apk add --no-cache make git
WORKDIR /plugin
COPY . .
RUN make binary

FROM golang:1.26.1-alpine3.22@sha256:07e91d24f6330432729082bb580983181809e0a48f0f38ecde26868d4568c6ac
RUN addgroup -g 1001 -S appgroup && adduser -u 1001 -S appuser -G appgroup

RUN mkdir -p /.privateer/bin && chown -R appuser:appgroup /.privateer
WORKDIR /.privateer/bin
USER appuser

COPY --from=core /app/privateer .
COPY --from=plugin /plugin/github-repo .
COPY --from=plugin /plugin/container-entrypoint.sh .

# The config file must be provided at run time.
# example: docker run -v /path/to/config.yml:/.privateer/config.yml privateer-image
CMD ["./container-entrypoint.sh"]
