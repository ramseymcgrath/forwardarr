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
