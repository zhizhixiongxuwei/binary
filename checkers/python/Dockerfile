ARG PYTHON_RUNTIME_IMAGE=python:3.13.15-slim-bookworm

FROM ${PYTHON_RUNTIME_IMAGE}
WORKDIR /opt/binaryscan/python-checker
COPY --chmod=0555 src/checker.py ./checker.py
RUN rm -rf \
      /usr/local/bin/pip \
      /usr/local/bin/pip3 \
      /usr/local/bin/pip3.13 \
      /usr/local/lib/python3.13/ensurepip \
      /usr/local/lib/python3.13/site-packages/pip \
      /usr/local/lib/python3.13/site-packages/pip-*.dist-info \
    && chown -R 10001:10001 /opt/binaryscan/python-checker
USER 10001:10001
ENV HOME=/tmp TMPDIR=/tmp PYTHONUNBUFFERED=1
EXPOSE 8080
ENTRYPOINT ["python3", "/opt/binaryscan/python-checker/checker.py"]
