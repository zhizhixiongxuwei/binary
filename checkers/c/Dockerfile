ARG JAVA_BUILD_IMAGE=maven:3.9.11-eclipse-temurin-21
ARG JAVA_RUNTIME_IMAGE=eclipse-temurin:21-jre-jammy

FROM ${JAVA_BUILD_IMAGE} AS build
WORKDIR /src
COPY pom.xml ./
COPY src ./src
RUN mvn -B -DskipTests package

FROM ${JAVA_RUNTIME_IMAGE}
WORKDIR /opt/binaryscan/c-checker
COPY --from=build --chmod=0444 /src/target/c-checker.jar ./checker.jar
RUN chown -R 10001:10001 /opt/binaryscan/c-checker
USER 10001:10001
ENV HOME=/tmp TMPDIR=/tmp
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/opt/binaryscan/c-checker/checker.jar"]
