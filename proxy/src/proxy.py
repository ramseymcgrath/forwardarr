import os
import re
import time
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

REGEX_PATTERNS = {
    'apikey': r'^[a-f0-9]{32}$',
    'imdbid': r'^tt\d{7,8}$',
    'o': r'^(json|xml)$',
}

INDEXER_URLS_JSON = os.environ.get('INDEXER_URLS_JSON', '/config/indexer_config.json')

API_KEYS_FILE = os.environ.get('API_KEYS_FILE', '/config/api_keys.json')

try:
    with open(API_KEYS_FILE, 'r') as file:
        CLIENT_API_KEY_MAP = json.load(file)
except Exception as e:
    app.logger.error(f"Error loading API keys from '{API_KEYS_FILE}': {e}")
    CLIENT_API_KEY_MAP = {}

try:
    with open(INDEXER_URLS_JSON, 'r') as file:
        INDEXER_NAME_MAP = json.load(file)
except Exception as e:
    app.logger.error(f"Error loading name map from '{INDEXER_NAME_MAP}': {e}")
    INDEXER_NAME_MAP = {}

INDEXER_NAME_PATTERN = r'^\w+$'

@app.route('/<indexer_name>/api', methods=['GET'])
def proxy(indexer_name):
    start_time = time.time()
    statsd.increment('newznab_proxy.request.count', tags=[f'indexer:{indexer_name}'])

    if not re.match(INDEXER_NAME_PATTERN, indexer_name):
        return Response("Invalid indexer name format.", status=400)

    if indexer_name not in INDEXER_URLS:
        return Response(f"Indexer '{indexer_name}' not found.", status=404)

    NEWZNAB_SERVER_URL = INDEXER_NAME_MAP[indexer_name]

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

        client_apikey = validated_params.get('apikey')
        if client_apikey:
            client_keys = CLIENT_API_KEY_MAP.get(client_apikey)
            if client_keys:
                actual_apikey = client_keys.get(indexer_name)
                if actual_apikey:
                    validated_params['apikey'] = actual_apikey
                else:
                    statsd.increment('newznab_proxy.invalid_api_key', tags=[f'indexer:{indexer_name}'])
                    return Response("Access denied for this indexer.", status=403)
            else:
                statsd.increment('newznab_proxy.invalid_api_key')
                return Response("Invalid API key.", status=403)
        else:
            return Response("API key is required.", status=400)

        response = requests.get(f"{NEWZNAB_SERVER_URL}/api", params=validated_params)

        duration = time.time() - start_time
        statsd.timing('newznab_proxy.response.time', duration * 1000, tags=[f'indexer:{indexer_name}'])
        statsd.increment('newznab_proxy.response.status_code', tags=[f'status_code:{response.status_code}', f'indexer:{indexer_name}'])

        proxied_response = Response(
            response.content,
            status=response.status_code,
            content_type=response.headers.get('Content-Type'),
        )

        return proxied_response

    except Exception as e:
        statsd.increment('newznab_proxy.error.count', tags=[f'indexer:{indexer_name}'])
        app.logger.error(f"Error occurred for indexer '{indexer_name}': {e}")
        return Response("Internal server error.", status=500)

if __name__ == '__main__':
    # Use '0.0.0.0' to allow connections from outside the container
    app.run(host='0.0.0.0', port=8080)
