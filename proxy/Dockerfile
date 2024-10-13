FROM python:3.9-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY ./src/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY ./src/proxy.py /app

# We don't really need to expose any ports for this service, but its possible
# EXPOSE 8080

ENV NEWZNAB_SERVER_URL=https://your-target-newznab-server.com
ENV API_KEYS_FILE=/app/api_keys.json
ENV DD_AGENT_HOST=localhost
ENV DD_DOGSTATSD_PORT=8125

CMD ["python", "proxy.py"]
