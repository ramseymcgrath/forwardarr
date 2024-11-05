ARG FUNCTION_DIR

FROM python:3.8-slim
ARG FUNCTION_DIR

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p ${FUNCTION_DIR}
COPY ./proxy/src/requirements.txt ${FUNCTION_DIR}/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt --target ${FUNCTION_DIR} awslambdaric
COPY ./proxy/src/proxy.py ${FUNCTION_DIR}/proxy.py
FROM python:3.12-slim

EXPOSE 8080
ENV INDEXER_URLS_JSON=/config/indexer_urls.json
ENV API_KEYS_FILE=/config/api_keys.json
ENV PARAMETERS_CONFIG_FILE = /config/allowed_parameters.json
ENV DD_AGENT_HOST=localhost
ENV DD_DOGSTATSD_PORT=8125
RUN pip install "ddtrace>=2.9.3"
ENV DD_IAST_ENABLED=true

CMD ["ddtrace-run", "python", "proxy.py"]
