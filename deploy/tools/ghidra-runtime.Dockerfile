ARG GHIDRA_JDK_IMAGE=eclipse-temurin:21-jdk-jammy
FROM ${GHIDRA_JDK_IMAGE}

USER root
COPY --chmod=0444 ghidra/ghidra.zip /tmp/ghidra.zip
COPY --chmod=0444 ghidra/executable-files.txt /tmp/ghidra-executable-files.txt
RUN mkdir -p /opt/ghidra-extract \
    && cd /opt/ghidra-extract \
    && /opt/java/openjdk/bin/jar --extract --file /tmp/ghidra.zip \
    && root=$(find /opt/ghidra-extract -mindepth 1 -maxdepth 1 -type d -name 'ghidra_*' -print) \
    && test -n "$root" \
    && test "$(printf '%s\n' "$root" | wc -l)" -eq 1 \
    && mv "$root" /opt/ghidra \
    && while IFS= read -r relative; do test -f "/opt/ghidra/$relative" && chmod 0555 "/opt/ghidra/$relative"; done < /tmp/ghidra-executable-files.txt \
    && grep -Fx 'DATA SEARCH IGNORE DIR: yajsw-stable-13.18' /opt/ghidra/Ghidra/Features/GhidraServer/Module.manifest \
    && rm -rf /opt/ghidra/Ghidra/Features/GhidraServer/data/yajsw-stable-13.18 \
    && rm -rf /opt/ghidra-extract /tmp/ghidra.zip /tmp/ghidra-executable-files.txt \
    && test -x /opt/ghidra/support/analyzeHeadless

ENV PATH=/opt/java/openjdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    JAVA_HOME=/opt/java/openjdk \
    HOME=/tmp \
    TMPDIR=/tmp

LABEL org.opencontainers.image.title="BinaryScan Ghidra runtime" \
      com.binaryscan.dependency-role="ghidra" \
      com.binaryscan.ghidra-version="12.1.3"

USER 10001:10001
WORKDIR /tmp
ENTRYPOINT []
CMD ["/opt/java/openjdk/bin/java", "-version"]
