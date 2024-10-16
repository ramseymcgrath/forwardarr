# forwardarr
Forwardarr enables you to proxy usenet queries from multiple clients to multiple indexers though a single endpoint. Client access tokens and allowed servers can be managed individually and wrapped into a single token. It can serve as a proxy from internal clients to the internet, and allow for more complex network routing. It also allows clients to use multiple indexers easily with a single api key.

## Getting started

### Deployment

Generate 2 configuration files:

`user_keys.json` should contain a unique 24 hex api key for each user, and a map of their indexer api keys and optional params. See [the example](/examples/user_keys.json.example)

`indexer_urls.json` should contain a list of indexers with their name and some optional parameters. See [the example](/examples/indexer_urls.json.example)

Mount the files to the docker container's `/config` directory and hit play to launch forwardarr. See the [docker compose example](/docker-compose.yaml)

### Usage

When configuring your usenet client, replace the indexer url with your own url with a path to the target indexer. For example `https://indexers.myforwardarrtestsite.com/indexer1/api`. Use `apikey=your_forwardarrapikey` for access but the remaining indexer queries can match the ones expected by your target indexer.

## Connectivity

Forwardarr provides a level of ssl validation and validates query params and headers, but does not expose an ssl endpoint. A private access tunnel or HTTPs proxy should be used.

## Datadog Monitoring

Statsd monitoring is enabled by default using the datadog library. Any statsd agent with a udp endpoint should be compatible but [Datadog](https://datadoghq.com) is recommended
