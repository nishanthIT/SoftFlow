# MinIO's community container repositories are no longer dependable.
# Build the official security release from source instead of pulling minio/minio.
FROM golang:1.25-bookworm AS build
ARG MINIO_RELEASE=RELEASE.2025-10-15T17-29-55Z
WORKDIR /src
RUN curl --fail --location --retry 3 \
    "https://codeload.github.com/minio/minio/tar.gz/refs/tags/${MINIO_RELEASE}" \
    | tar --extract --gzip --strip-components=1
ENV CGO_ENABLED=0
RUN go build -p 2 -trimpath -o /out/minio .

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 minio && useradd --uid 10001 --gid 10001 --no-create-home minio \
    && mkdir -p /data && chown minio:minio /data
COPY --from=build /out/minio /usr/local/bin/minio
USER 10001:10001
EXPOSE 9000
ENTRYPOINT ["/usr/local/bin/minio"]
CMD ["server", "/data"]
