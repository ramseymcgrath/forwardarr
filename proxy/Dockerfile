FROM rust:bullseye

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl python && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
EXPOSE 8080
ENV INDEXER_URLS_JSON=/config/indexer_urls.json
ENV API_KEYS_FILE=/config/api_keys.json
ENV PARAMETERS_CONFIG_FILE = /config/allowed_parameters.json
ENV DD_AGENT_HOST=localhost
ENV DD_DOGSTATSD_PORT=8125
ENV DD_IAST_ENABLED=true
ENV DD_SERVICE=forwardarr
ENV DD_ENV=prod
ENV DD_LOGS_INJECTION=true 
ENV DD_PROFILING_ENABLED=true
ENV DD_APPSEC_ENABLED=true
ENV DD_APPSEC_SCA_ENABLED=true

COPY ./proxy/src/requirements.txt ./requirements.txt
RUN python -m pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt
RUN mkdir -p /config
COPY ./proxy/src/proxy.py /app/proxy.py

CMD ["ddtrace-run", "python", "proxy.py"]
