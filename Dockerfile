FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS core
RUN apk add --no-cache wget tar unzip

WORKDIR /app
ARG VERSION=0.22.0
ARG PLATFORM=Linux_x86_64  # Change this based on your target system

RUN wget https://github.com/privateerproj/privateer/releases/download/v${VERSION}/privateer_${PLATFORM}.tar.gz
RUN tar -xzf privateer_${PLATFORM}.tar.gz

FROM golang:1.26.4-alpine3.22@sha256:727cfc3c40be55cd1bc9a4a059406b28a059857e3be752aa9d09531e12c20c56 AS plugin
RUN apk add --no-cache make git
WORKDIR /plugin
COPY . .
RUN make binary

FROM golang:1.26.4-alpine3.22@sha256:727cfc3c40be55cd1bc9a4a059406b28a059857e3be752aa9d09531e12c20c56
RUN addgroup -g 1001 -S appgroup && adduser -u 1001 -S appuser -G appgroup

RUN mkdir -p /.privateer/bin && chown -R appuser:appgroup /.privateer
WORKDIR /.privateer/bin
USER appuser

COPY --from=core /app/pvtr .
COPY --from=plugin /plugin/github-repo .
COPY --from=plugin /plugin/container-entrypoint.sh .

# Register the plugin in the manifest so pvtr treats it as installed.
# pvtr only runs plugins listed in plugins.json; without this, `pvtr run`
# exits with "requested plugin that is not installed: github-repo".
# Keep in sync with the manifest written by .github/scripts/ci.sh.
RUN printf '%s\n' '{"plugins":[{"name":"github-repo","version":"local","binaryPath":"github-repo"}]}' > plugins.json

# The config file must be provided at run time.
# example: docker run -v /path/to/config.yml:/.privateer/config.yml privateer-image
CMD ["./container-entrypoint.sh"]
