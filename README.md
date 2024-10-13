# forwardarr
This is an example configuration to forward newznab queries from external clients though a single endpoint. Its expected that traffic will come through cloudflare private IPs to hit the application instead of the internet. 

## Getting started

For ssl connectivity, get a cloudflare private access origin certificate and add it to the nginx docker code using

```sh
mkdir -p ./nginx/ssl/private
mv mykey.key ./nginx/ssl/private/origin.key
chmod 600 ./nginx/ssl/private/origin.key
```

## Cloudflare support

Cloudflare is enabled by default to front requests to the proxy app. You'll need to setup an account and cloudflare zero trust publisher to forward traffic through to nginx (and along to the proxy). 

### Cloudflare origin ssl cert

Download a cloudflare origin cert for your domain and use the bash above to add it to nginx.

### Cloudflare source IPs

To enforce traffic originating only from cloudflare publishers, you'll need to add their source ips to the nginx whitelist. Localhost will be allowed as well for local testing and to enable local publishers. Use the following script to auto generate a full list of allowed ips for your nginx configuration

```sh
#!/bin/bash

# Download the latest Cloudflare IPs
curl https://www.cloudflare.com/ips-v4 -o ./nginx/conf.d/cf-ips.txt
curl https://www.cloudflare.com/ips-v6 >> ./nginx/conf.d/cf-ips.txt

# Generate the cloudflare.conf file
echo "" > ./nginx/conf.d/cloudflare.conf
echo "set_real_ip_from 127.0.0.1;" >> ./nginx/conf.d/cloudflare.conf
echo "set_real_ip_from localhost;" >> ./nginx/conf.d/cloudflare.conf
## add additional trusted IPs here
## below will add cloudflare IPs to the list
while read cf_ip; do
    echo "set_real_ip_from $cf_ip;" >> ./nginx/conf.d/cloudflare.conf
done < ./nginx/conf.d/cf-ips.txt
echo "real_ip_header CF-Connecting-IP;" >> ./nginx/conf.d/cloudflare.conf
```

## Datadog support

Datadog monitoring is enabled by default using dogstatsd. You'll need an agent listening on localhost:8125 to collect the custom metrics. 
