import os
import re
import sys
import time
import json
import hashlib
import traceback
import logging
from flask import Flask, request, Response, make_response
import requests
from datadog import initialize, statsd

app = Flask(__name__)

app.logger.setLevel(logging.DEBUG)

# Create a handler to output logs to stderr
handler = logging.StreamHandler()
handler.setLevel(logging.DEBUG)

# Create a formatter and set it for the handler
formatter = logging.Formatter(
    '[%(asctime)s] %(levelname)s in %(module)s: %(message)s'
)
handler.setFormatter(formatter)

# Add the handler to the app's logger
if not app.logger.handlers:
    app.logger.addHandler(handler)

options = {
    'statsd_host': os.environ.get('DD_AGENT_HOST', 'localhost'),
    'statsd_port': int(os.environ.get('DD_DOGSTATSD_PORT', 8125)),
}
initialize(**options)

# Allowed parameters and their expected types
allowed_params = {
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
    'id': int,
    'r': str,
}

# Regular expressions for parameter validation
regex_patterns = {
    'apikey': r'^[A-Fa-f0-9]{24}$'
    'imdbid': r'^tt\d{7,8}$',
    'o': r'^(json|xml)$',
}

# Configuration file paths
INDEXER_URLS_JSON = os.environ.get('INDEXER_URLS_JSON', '/config/indexer_config.json')
API_KEYS_FILE = os.environ.get('API_KEYS_FILE', '/config/api_keys.json')

# Load API keys mapping
try:
    with open(API_KEYS_FILE, 'r') as file:
        client_api_key_map = json.load(file)
except FileNotFoundError:
    app.logger.error(f"API keys file not found: '{API_KEYS_FILE}'")
    sys.exit(1)
except json.JSONDecodeError as e:
    app.logger.error(f"Error decoding JSON from '{API_KEYS_FILE}': {e}")
    sys.exit(1)
except Exception as e:
    app.logger.error(f"Error loading API keys from '{API_KEYS_FILE}': {e}")
    sys.exit(1)

# Load indexer URLs mapping
try:
    with open(INDEXER_URLS_JSON, 'r') as file:
        indexer_name_map = json.load(file)
except FileNotFoundError:
    app.logger.error(f"Indexer URLs file not found: '{INDEXER_URLS_JSON}'")
    sys.exit(1)
except json.JSONDecodeError as e:
    app.logger.error(f"Error decoding JSON from '{INDEXER_URLS_JSON}': {e}")
    sys.exit(1)
except Exception as e:
    app.logger.error(f"Error loading indexer URLs from '{INDEXER_URLS_JSON}': {e}")
    sys.exit(1)

# Indexer name validation pattern
indexer_name_pattern = r'^\w+$'

@app.route('/<indexer_name>/api', methods=['GET'])
def proxy(indexer_name):
    start_time = time.time()
    statsd.increment('newznab_proxy.request.count', tags=[f'indexer:{indexer_name}'])

    if not re.match(indexer_name_pattern, indexer_name):
        return Response("Invalid indexer name format.", status=400)

    if indexer_name not in indexer_name_map:
        return Response(f"Indexer '{indexer_name}' not found.", status=404)

    usenet_server_url = indexer_name_map[indexer_name]['url']

    # Different indexers use different API key parameters
    usenet_api_param = indexer_name_map[indexer_name]['api_param']

    try:
        params = request.args.to_dict(flat=False)
        validated_params = {}

        # Validate and normalize parameters
        for param, values in params.items():
            if param in allowed_params:
                expected_type = allowed_params[param]
                validated_values = []
                for value in values:
                    try:
                        if expected_type == int:
                            validated_values.append(int(value))
                        else:
                            value = value.strip()
                            if len(value) > 255:
                                return Response(f"Parameter '{param}' is too long.", status=400)
                            if param in regex_patterns and not re.match(regex_patterns[param], value):
                                return Response(f"Parameter '{param}' has an invalid format.", status=400)
                            validated_values.append(value)
                    except ValueError:
                        statsd.increment('newznab_proxy.validation_error', tags=[f'parameter:{param}', f'indexer:{indexer_name}'])
                        return Response(f"Invalid value for parameter '{param}'.", status=400)
                if len(validated_values) == 1:
                    validated_params[param] = validated_values[0]
                else:
                    validated_params[param] = validated_values
                statsd.increment('newznab_proxy.parameter.usage', tags=[f'parameter:{param}', f'indexer:{indexer_name}'])
            else:
                return Response(f"Parameter '{param}' is not allowed.", status=400)

        # API key validation and substitution
        client_apikey = validated_params.get('apikey')
        if client_apikey:
            statsd.increment('newznab_proxy.request.per_api_key', tags=[f'client_apikey:{client_apikey}', f'indexer:{indexer_name}'])
            # if invalid API key, return 403
            if client_apikey not in client_api_key_map.keys():
                statsd.increment('newznab_proxy.invalid_client_api_key', tags=[f'indexer:{indexer_name}'])
                return Response("Invalid API key.", status=403)

            # get client keys from the json map
            client_keys = client_api_key_map.get(client_apikey)

            # if no client keys, return 403
            if client_keys:
                indexer_key = client_keys.get(indexer_name)
                # if indexer key exists for client, use it
                if indexer_key:
                    validated_params[indexer] = indexer_key
                else:
                    statsd.increment('newznab_proxy.access_denied', tags=[f'indexer:{indexer_name}'])
                    return Response("Access denied for this indexer.", status=403)
            else:
                statsd.increment('newznab_proxy.invalid_api_key', tags=[f'indexer:{indexer_name}'])
                return Response("Invalid API key.", status=403)
        else:
            return Response("API key is required.", status=400)

        upstream_start_time = time.time()
        app.logger.debug(f"Client API Key: {client_apikey}")
        app.logger.debug(f"Indexer Name: {indexer_name}")
        app.logger.debug(f"Actual API Key Retrieved: {bool(indexer_key)}")
        app.logger.debug(f"Connecting to {usenet_server_url}/api")

        # just making a new map to look cleaner
        indexer_query = validated_params.copy()
        try:
            if api_key_params != "apikey":
                # remove the api key from the query if we are using a different param
                indexer_query.remove('apikey')
                # add the other api key to the query
                indexer_query.append({usenet_api_param: indexer_key})
            # make the request
            response = requests.get(f"{usenet_server_url}/api", params=indexer_query, timeout=10)
        # handle the different exceptions
        except requests.exceptions.Timeout:
            statsd.increment('newznab_proxy.upstream.timeout', tags=[f'indexer:{indexer_name}'])
            app.logger.error(f"Timeout when contacting indexer '{indexer_name}'.")
            return Response("Indexing server timed out.", status=504)
        except requests.exceptions.ConnectionError:
            statsd.increment('newznab_proxy.upstream.connection_error', tags=[f'indexer:{indexer_name}'])
            app.logger.error(f"Connection error when contacting indexer '{indexer_name}'.")
            return Response("Error connecting to the indexing server.", status=502)
        except requests.exceptions.RequestException as e:
            statsd.increment('newznab_proxy.upstream.error', tags=[f'indexer:{indexer_name}'])
            app.logger.error(f"HTTP request failed for indexer '{indexer_name}': {e}")
            return Response("Error contacting the indexer.", status=502)

        upstream_duration = time.time() - upstream_start_time
        statsd.timing('newznab_proxy.upstream.response.time', upstream_duration * 1000, tags=[f'indexer:{indexer_name}'])

        duration = time.time() - start_time
        statsd.timing('newznab_proxy.response.time', duration * 1000, tags=[f'indexer:{indexer_name}'])
        statsd.increment('newznab_proxy.response.status_code', tags=[f'status_code:{response.status_code}', f'indexer:{indexer_name}'])

        response_size = len(response.content)
        statsd.histogram('newznab_proxy.response.size', response_size, tags=[f'indexer:{indexer_name}'])

        SLOW_REQUEST_THRESHOLD = 2  # seconds
        if duration > SLOW_REQUEST_THRESHOLD:
            statsd.increment('newznab_proxy.slow_request', tags=[f'indexer:{indexer_name}'])
        if 400 <= response.status_code < 500:
            statsd.increment('newznab_proxy.client_error', tags=[f'status_code:{response.status_code}', f'indexer:{indexer_name}'])
        elif 500 <= response.status_code < 600:
            statsd.increment('newznab_proxy.server_error', tags=[f'status_code:{response.status_code}', f'indexer:{indexer_name}'])

        content_type = response.headers.get('Content-Type', 'unknown')
        statsd.increment('newznab_proxy.response.content_type', tags=[f'content_type:{content_type}', f'indexer:{indexer_name}'])

        proxied_response = make_response(response.content, response.status_code)
        for header_name, header_value in response.headers.items():
            proxied_response.headers[header_name] = header_value
        return proxied_response

    except Exception as e:
        exception_type = type(e).__name__
        statsd.increment('newznab_proxy.exception.count', tags=[f'indexer:{indexer_name}', f'exception_type:{exception_type}'])
        app.logger.error(f"Unhandled exception for indexer '{indexer_name}': {e}\n{traceback.format_exc()}")
        return Response("Internal server error.", status=500)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
