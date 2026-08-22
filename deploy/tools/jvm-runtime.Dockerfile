ARG JAVA_RUNTIME_IMAGE=eclipse-temurin:21-jre-jammy
FROM ${JAVA_RUNTIME_IMAGE}

USER root
RUN mkdir -p /opt/bytecode-tools/vineflower /opt/bytecode-tools/cfr /opt/bytecode-tools/jadx/lib
COPY --chmod=0444 jvm/vineflower.jar /opt/bytecode-tools/vineflower/vineflower.jar
COPY --chmod=0444 jvm/cfr.jar /opt/bytecode-tools/cfr/cfr.jar
COPY --chmod=0444 jvm/jadx-all.jar /opt/bytecode-tools/jadx/lib/jadx-all.jar

ENV PATH=/opt/java/openjdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    JAVA_HOME=/opt/java/openjdk \
    HOME=/tmp \
    TMPDIR=/tmp \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

LABEL org.opencontainers.image.title="BinaryScan JVM decompiler tools" \
      com.binaryscan.dependency-role="jvm-tools" \
      com.binaryscan.vineflower-version="1.12.0" \
      com.binaryscan.cfr-version="0.152" \
      com.binaryscan.jadx-version="1.5.6"

USER 10001:10001
WORKDIR /tmp
ENTRYPOINT []
CMD ["/opt/java/openjdk/bin/java", "-version"]
