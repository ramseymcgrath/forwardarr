import os
import re
import time
import hashlib
import json
from flask import Flask, request, Response
import requests
from datadog import initialize, statsd

app = Flask(__name__)

options = {
    'statsd_host': os.environ.get('DD_AGENT_HOST', 'localhost'),
    'statsd_port': int(os.environ.get('DD_DOGSTATSD_PORT', 8125)),
}

initialize(**options)

# Newznab server URL
NEWZNAB_SERVER_URL = os.environ.get('NEWZNAB_SERVER_URL', 'https://newznab-server.com')

# Allowed parameters and their expected types
ALLOWED_PARAMS = {
    't': str,
    'q': str,
    'apikey': str,
    'cat': str,
    'limit': int,
    'offset': int,
    'rid': int,
    'imdbid': str,
    'tvdbid': int,
    'season': int,
    'ep': int,
    'o': str,
    'extended': int,
}

# Regular expressions for validating parameter values
REGEX_PATTERNS = {
    'apikey': r'^[a-f0-9]{64}$',   # SHA-256 hash
    'imdbid': r'^tt\d{7,8}$',
    'o': r'^(json|xml)$',
}

# Load API keys from a JSON file
API_KEYS_FILE = os.environ.get('API_KEYS_FILE', 'api_keys.json')

try:
    with open(API_KEYS_FILE, 'r') as file:
        API_KEY_MAP = json.load(file)
except Exception as e:
    app.logger.error(f"Error loading API keys from '{API_KEYS_FILE}': {e}")
    API_KEY_MAP = {}

@app.route('/api', methods=['GET'])
def proxy():
    start_time = time.time()
    statsd.increment('newznab_proxy.request.count')

    try:
        params = request.args.to_dict()
        validated_params = {}

        for param, value in params.items():
            if param in ALLOWED_PARAMS:
                expected_type = ALLOWED_PARAMS[param]
                try:
                    if expected_type == int:
                        validated_params[param] = int(value)
                    else:
                        value = value.strip()
                        if len(value) > 255:
                            return Response(f"Parameter '{param}' is too long.", status=400)
                        if param in REGEX_PATTERNS:
                            if not re.match(REGEX_PATTERNS[param], value):
                                return Response(f"Parameter '{param}' has an invalid format.", status=400)
                        validated_params[param] = value
                except ValueError:
                    return Response(f"Invalid value for parameter '{param}'.", status=400)
            else:
                return Response(f"Parameter '{param}' is not allowed.", status=400)

        hashed_apikey = validated_params.get('apikey')
        if hashed_apikey:
            actual_apikey = API_KEY_MAP.get(hashed_apikey)
            if actual_apikey:
                validated_params['apikey'] = actual_apikey
            else:
                statsd.increment('newznab_proxy.invalid_api_key')
                return Response("Invalid API key.", status=403)
        else:
            return Response("API key is required.", status=400)

        response = requests.get(f"{NEWZNAB_SERVER_URL}/api", params=validated_params)
        duration = time.time() - start_time
        statsd.timing('newznab_proxy.response.time', duration * 1000)
        statsd.increment('newznab_proxy.response.status_code', tags=[f'status_code:{response.status_code}'])
        proxied_response = Response(
            response.content,
            status=response.status_code,
            content_type=response.headers.get('Content-Type'),
        )
        return proxied_response

    except Exception as e:
        statsd.increment('newznab_proxy.error.count')
        app.logger.error(f"Error occurred: {e}")
        return Response("Internal server error.", status=500)

if __name__ == '__main__':
    # Use '0.0.0.0' to allow connections from outside the container
    app.run(host='0.0.0.0', port=8080)
