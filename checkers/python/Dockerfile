ARG PYTHON_RUNTIME_IMAGE=python:3.13.7-slim-bookworm

FROM ${PYTHON_RUNTIME_IMAGE}
WORKDIR /opt/binaryscan/python-checker
COPY --chmod=0555 src/checker.py ./checker.py
RUN chown -R 10001:10001 /opt/binaryscan/python-checker
USER 10001:10001
ENV HOME=/tmp TMPDIR=/tmp PYTHONUNBUFFERED=1
EXPOSE 8080
ENTRYPOINT ["python3", "/opt/binaryscan/python-checker/checker.py"]
