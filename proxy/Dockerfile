FROM python:3.9-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY ./proxy/src/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
RUN mkdir -p /config
COPY ./proxy/src/proxy.py /app/proxy.py
EXPOSE 6060
ENV INDEXER_URLS_JSON=/config/indexer_urls.json
ENV API_KEYS_FILE=/config/api_keys.json
ENV DD_AGENT_HOST=localhost
ENV DD_DOGSTATSD_PORT=8125

CMD ["python", "proxy.py"]
