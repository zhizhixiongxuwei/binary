ARG TRIVY_SOURCE_IMAGE=public.ecr.aws/aquasecurity/trivy:0.74.0
FROM ${TRIVY_SOURCE_IMAGE} AS trivy

FROM scratch
COPY --from=trivy --chmod=0555 /usr/local/bin/trivy /usr/local/bin/trivy
COPY --chown=10001:10001 --chmod=0555 trivy /opt/trivy-cache

ENV HOME=/tmp \
    TMPDIR=/tmp \
    TRIVY_DISABLE_TELEMETRY=true \
    TRIVY_OFFLINE_SCAN=true \
    TRIVY_SKIP_DB_UPDATE=true \
    TRIVY_SKIP_JAVA_DB_UPDATE=true \
    TRIVY_SKIP_VERSION_CHECK=true

LABEL org.opencontainers.image.title="BinaryScan Trivy offline runtime" \
      com.binaryscan.dependency-role="trivy" \
      com.binaryscan.trivy-version="0.74.0"

USER 10001:10001
WORKDIR /tmp
ENTRYPOINT ["/usr/local/bin/trivy"]
CMD ["version", "--format", "json"]
