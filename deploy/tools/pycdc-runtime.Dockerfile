ARG PYCDC_BUILD_IMAGE=alpine:3.22.5
ARG PYCDC_RUNTIME_IMAGE=alpine:3.22.5

FROM ${PYCDC_BUILD_IMAGE} AS build
RUN apk add --no-cache cmake g++ make
COPY pycdc/source.tar.gz /tmp/source.tar.gz
RUN mkdir -p /src /build \
    && tar -xzf /tmp/source.tar.gz -C /src --strip-components=1 \
    && cmake -S /src -B /build -DCMAKE_BUILD_TYPE=Release \
    && cmake --build /build --parallel 2 \
    && test -x /build/pycdc

FROM ${PYCDC_RUNTIME_IMAGE}
RUN apk add --no-cache libstdc++
COPY --from=build --chmod=0555 /build/pycdc /opt/bytecode-tools/pycdc/pycdc
COPY --from=build --chmod=0444 /src/LICENSE /usr/share/licenses/pycdc/LICENSE

ENV HOME=/tmp TMPDIR=/tmp
LABEL org.opencontainers.image.title="BinaryScan pycdc tools" \
      com.binaryscan.dependency-role="pycdc" \
      com.binaryscan.pycdc-commit="b4289760970dbc399684f1e155ec6d1ea1cc787e"

USER 10001:10001
WORKDIR /tmp
ENTRYPOINT []
CMD ["/opt/bytecode-tools/pycdc/pycdc", "--help"]
