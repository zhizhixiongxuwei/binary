ARG JAVA_BUILD_IMAGE=maven:3.9.11-eclipse-temurin-21
ARG JAVA_RUNTIME_IMAGE=eclipse-temurin:21-jre-jammy

FROM ${JAVA_BUILD_IMAGE} AS spotbugs
RUN curl -fsSL --retry 3 -o /tmp/spotbugs.zip \
      https://repo.maven.apache.org/maven2/com/github/spotbugs/spotbugs/4.10.4/spotbugs-4.10.4.zip \
    && echo '771c8702beb2b4b6aa20df87ea85f22fda7280c7ce36fce4077b7b3c076d1e14  /tmp/spotbugs.zip' | sha256sum -c - \
    && cd /tmp && jar xf spotbugs.zip \
    && mkdir -p /opt/spotbugs \
    && cp -r spotbugs-4.10.4/lib spotbugs-4.10.4/LICENSE*.txt /opt/spotbugs/

FROM ${JAVA_BUILD_IMAGE} AS build
WORKDIR /src
COPY pom.xml ./
COPY src ./src
RUN mvn -B -DskipTests package

FROM ${JAVA_RUNTIME_IMAGE}
WORKDIR /opt/binaryscan/java-checker
COPY --from=build --chmod=0444 /src/target/java-checker.jar ./checker.jar
COPY --from=spotbugs /opt/spotbugs /opt/spotbugs
RUN chown -R 10001:10001 /opt/binaryscan/java-checker
USER 10001:10001
ENV HOME=/tmp TMPDIR=/tmp
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/opt/binaryscan/java-checker/checker.jar"]
