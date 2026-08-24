ARG BUILD_IMAGE=public.ecr.aws/docker/library/golang:1.26.7-bookworm
FROM ${BUILD_IMAGE}

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        gcc-mingw-w64-x86-64 \
        p7zip-full \
        rpm \
    && apt-get clean \
    && find /var/lib/apt/lists -mindepth 1 -delete

WORKDIR /work
