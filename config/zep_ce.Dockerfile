# Build of Zep CE for this study.
#
# Upstream legacy/Dockerfile.ce pins golang:1.22.5, but the checked-in src/go.mod now
# requires go >= 1.25, and legacy/go.work still declares 1.21.5, so the published
# build recipe no longer compiles. We keep the target repository pristine and fix both
# points here instead: a newer toolchain, and GOWORK=off so the stale workspace file
# does not veto the module's own go directive. Nothing about Zep's behaviour changes.

FROM golang:1.25-bookworm AS build
ENV GOWORK=off
RUN mkdir /app
WORKDIR /app
COPY . .
WORKDIR /app/src
RUN go mod download
RUN go build -o /app/out/bin/zep .

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /app/out/bin/zep /app/
COPY zep.yaml /app/
EXPOSE 8000
ENTRYPOINT ["/app/zep"]
