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
from urllib.parse import urlparse
from datadog import initialize, statsd

app = Flask(__name__)

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[logging.StreamHandler()],
)
app.logger.setLevel(logging.DEBUG)

# Initialize Datadog client
options = {
    "statsd_host": os.environ.get("DD_AGENT_HOST", "localhost"),
    "statsd_port": int(os.environ.get("DD_DOGSTATSD_PORT", 8125)),
}
initialize(**options)

# Configuration file paths
INDEXER_URLS_JSON = os.environ.get("INDEXER_URLS_JSON", "/config/indexer_config.json")
API_KEYS_FILE = os.environ.get("API_KEYS_FILE", "/config/api_keys.json")
PARAMETERS_CONFIG_FILE = os.environ.get("PARAMETERS_CONFIG_FILE", "/config/parameters.json")

# Load API keys mapping
try:
    with open(API_KEYS_FILE, "r") as file:
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
    with open(INDEXER_URLS_JSON, "r") as file:
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

# Load parameters configuration if available
try:
    with open(PARAMETERS_CONFIG_FILE, "r") as file:
        allowed_params = json.load(file)
except FileNotFoundError:
    app.logger.error(
        f"Parameters configuration file not found: '{PARAMETERS_CONFIG_FILE}'"
    )
except json.JSONDecodeError as e:
    app.logger.error(f"Error decoding JSON from '{PARAMETERS_CONFIG_FILE}': {e}")
except Exception as e:
    app.logger.error(
        f"Error loading parameters configuration from '{PARAMETERS_CONFIG_FILE}': {e}"
    )
allowed_params_api = allowed_params.get("api", {})
allowed_params_rss_imported = allowed_params.get("rss", {})
# Indexer name validation pattern
indexer_name_pattern = r"^\w+$"

# Allowed parameters and regex patterns for API route
regex_patterns_api = {
    "apikey": r"^[A-Fa-f0-9]{24}$",
}

# Allowed parameters and regex patterns for RSS route
allowed_params_rss = allowed_params_api.copy(allowed_params_rss_imported)
regex_patterns_rss = regex_patterns_api.copy()
allowed_params = allowed_params_api.copy()
regex_patterns = regex_patterns_api.copy()

def handle_request(indexer_name, request_type="api"):
    start_time = time.time()
    statsd.increment(
        f"forwardarr.{request_type}_request.count", tags=[f"indexer:{indexer_name}"]
    )

    # Validate indexer_name
    if not re.match(indexer_name_pattern, indexer_name):
        return Response("Invalid indexer name format.", status=400)

    if indexer_name not in indexer_name_map:
        return Response(f"Indexer '{indexer_name}' not found.", status=404)

    indexer_info = indexer_name_map[indexer_name]
    usenet_server_url = indexer_info["url"]

    ## Support a custom userid param
    if "api_param" in indexer_info:
        user_id_param = indexer_info["api_param"]
    else:
        user_id_param = "apikey"

    ## Support a custom timeout
    if "timeout" in indexer_info:
        timeout = indexer_info["timeout"]
    else:
        timeout = 60

    usenet_path = indexer_info.get(f"{request_type}_path", f"/{request_type}")

    # Select allowed parameters and regex patterns
    if request_type == "rss":
        allowed_params = allowed_params_rss
        regex_patterns = regex_patterns_rss
    else:
        allowed_params = allowed_params_api
        regex_patterns = regex_patterns_api
    try:
        params = request.args.to_dict(flat=False)
        validated_params = {}
        for param, values in params.items():
            if len(allowed_params) > 0 and param not in allowed_params:
                statsd.increment(
                    "forwardarr.parameter.rejected",
                    tags=[f"parameter:{param}", f"indexer:{indexer_name}"],
                )
                app.logger.debug(f"Rejected parameter: {param}")
                continue
            else:
                if param in allowed_params:
                    expected_type = allowed_params[param]
                else:
                    expected_type = str
                validated_values = []
                for value in values:
                    try:
                        if expected_type == int:
                            validated_values.append(int(value))
                        else:
                            value = value.strip()
                            if len(value) > 255:
                                return Response(
                                    f"Parameter '{param}' is too long.", status=400
                                )
                            if param in regex_patterns and not re.match(
                                regex_patterns[param], value
                            ):
                                return Response(
                                    f"Parameter '{param}' has an invalid format.",
                                    status=400,
                                )
                            validated_values.append(value)
                    except ValueError:
                        statsd.increment(
                            "forwardarr.validation_error",
                            tags=[f"parameter:{param}", f"indexer:{indexer_name}"],
                        )
                        return Response(
                            f"Invalid value for parameter '{param}'. Expected {expected_type}. Request failed.", status=400
                        )
                if len(validated_values) == 1:
                    validated_params[param] = validated_values[0]
                else:
                    validated_params[param] = validated_values
                statsd.increment(
                    "forwardarr.parameter.usage",
                    tags=[f"parameter:{param}", f"indexer:{indexer_name}"],
                )

        # API key validation and substitution
        client_apikey = validated_params.get("apikey")
        if client_apikey:
            statsd.increment(
                "forwardarr.request.per_api_key", tags=[f"indexer:{indexer_name}"]
            )
            if client_apikey not in client_api_key_map:
                statsd.increment(
                    "forwardarr.invalid_client_api_key",
                    tags=[f"indexer:{indexer_name}"],
                )
                return Response("Invalid API key.", status=403)
            client_keys = client_api_key_map[client_apikey]
            user_name = client_keys['user']
            statsd.increment(
                "forwardarr.request.per_user", tags=[f"user:{user_name}"]
            )
            if indexer_name not in client_keys:
                statsd.increment(
                    "forwardarr.access_denied", tags=[f"indexer:{indexer_name}", f"user:{user_name}"]
                )
                return Response("Access denied for this indexer.", status=403)
            indexer_key = client_keys[indexer_name]["key"]
            try:
                validated_params.update(client_keys[indexer_name]["extra_params"])
            except KeyError:
                pass
        else:
            return Response("API key is required.", status=400)

        # Only log hashed client API key for security
        client_apikey_hash = hashlib.sha256(client_apikey.encode()).hexdigest()[:8]
        app.logger.debug(f"Client API Key Hash: {client_apikey_hash}")
        app.logger.debug(f"Client Name: {client_keys.get('user')}")
        app.logger.debug(f"Indexer Name: {indexer_name}")
        app.logger.debug(f"Actual API Key Retrieved: {bool(indexer_key)}")
        app.logger.debug(f"Connecting to {usenet_server_url}{usenet_path}")
        is_grab = validated_params.get("t") == "get"
        if is_grab:
            app.logger.debug("Grab request detected.")
            statsd.increment(
                "forwardarr.request.grab", tags=[f"indexer:{indexer_name}", f"user:{user_name}"]
            )
        # Prepare the query parameters
        indexer_query = validated_params.copy()
        # Replace the API key with the indexer key if thats what the indexer uses
        if user_id_param == "apikey":
            indexer_query["apikey"] = indexer_key
        # Otherwise, add the indexer key to the query
        else:
            indexer_query.update({user_id_param: indexer_key})

        # Prepare headers
        headers = {
            "Host": urlparse(usenet_server_url).netloc,
            "Accept-Encoding": "gzip, deflate",
            "User-Agent": request.headers.get("User-Agent", "ForwardArr Proxy"),
        }

        app.logger.debug(f"Request headers: {headers}")
        app.logger.debug(f"Request parameters: {indexer_query}")
        upstream_start_time = time.time()
        # Make the request
        try:
            statsd.increment(
                "forwardarr.upstream.request.count",
                tags=[f"indexer:{indexer_name}", f"user:{user_name}"],
            )
            response = requests.get(
                f"{usenet_server_url}{usenet_path}",
                params=indexer_query,
                timeout=timeout,
                headers=headers,
                verify=True,
                stream=True,
            )
        except requests.exceptions.Timeout:
            statsd.increment(
                "forwardarr.upstream.timeout", tags=[f"indexer:{indexer_name}"]
            )
            app.logger.error(f"Timeout when contacting indexer '{indexer_name}'.")
            return Response("Indexing server timed out.", status=504)
        except requests.exceptions.ConnectionError:
            statsd.increment(
                "forwardarr.upstream.connection_error", tags=[f"indexer:{indexer_name}"]
            )
            app.logger.error(
                f"Connection error when contacting indexer '{indexer_name}'."
            )
            return Response("Error connecting to the indexing server.", status=502)
        except requests.exceptions.RequestException as e:
            statsd.increment(
                "forwardarr.upstream.error", tags=[f"indexer:{indexer_name}"]
            )
            app.logger.error(f"HTTP request failed for indexer '{indexer_name}': {e}")
            return Response("Error contacting the indexer.", status=502)

        upstream_duration = time.time() - upstream_start_time
        statsd.timing(
            "forwardarr.upstream.response.time",
            upstream_duration * 1000,
            tags=[f"indexer:{indexer_name}"],
        )
        duration = time.time() - start_time
        statsd.timing(
            "forwardarr.response.time",
            duration * 1000,
            tags=[f"indexer:{indexer_name}"],
        )
        statsd.increment(
            "forwardarr.response.status_code",
            tags=[f"status_code:{response.status_code}", f"indexer:{indexer_name}"],
        )

        # Content type and size
        content_type = response.headers.get("Content-Type", "unknown")
        response_size = response.headers.get("Content-Length", "unknown")
        statsd.histogram(
            "forwardarr.response.size",
            int(response_size) if response_size.isdigit() else 0,
            tags=[f"indexer:{indexer_name}"],
        )
        statsd.increment(
            "forwardarr.response.content_type",
            tags=[f"content_type:{content_type}", f"indexer:{indexer_name}"],
        )

        SLOW_REQUEST_THRESHOLD = 2  # seconds
        if duration > SLOW_REQUEST_THRESHOLD:
            statsd.increment(
                "forwardarr.slow_request", tags=[f"indexer:{indexer_name}"]
            )
        if 400 <= response.status_code < 500:
            statsd.increment(
                "forwardarr.client_error",
                tags=[f"status_code:{response.status_code}", f"indexer:{indexer_name}"],
            )
        elif 500 <= response.status_code < 600:
            statsd.increment(
                "forwardarr.server_error",
                tags=[f"status_code:{response.status_code}", f"indexer:{indexer_name}"],
            )

        # Stream the response back to the client
        def generate():
            try:
                for chunk in response.raw.stream(decode_content=False):
                    yield chunk
            except Exception as e:
                app.logger.error(f"Error streaming response: {e}")

        ## If the request is a grab request, we need to return the response headers
        if is_grab:
            # Ensure Content-Type is 'application/x-nzb'
            content_type = response.headers.get("Content-Type", "application/x-nzb")
            excluded_headers = [
                "content-length",
                "transfer-encoding",
                "connection",
                "content-type",
            ]
            response_headers = [
                (name, value)
                for (name, value) in response.raw.headers.items()
                if name.lower() not in excluded_headers
            ]
            response_headers.append(("Content-Type", content_type))

            content_disposition = response.headers.get("Content-Disposition")
            if content_disposition:
                response_headers.append(("Content-Disposition", content_disposition))
            else:
                response_headers.append(
                    ("Content-Disposition", 'attachment; filename="download.nzb"')
                )

            app.logger.debug(f"Response headers to client: {response_headers}")
            app.logger.debug(f"Response status code: {response.status_code}")

            return Response(generate(), response.status_code, response_headers)
        ## Otherwise, we can just return the response
        else:
            excluded_headers = ["content-length", "transfer-encoding", "connection"]
            response_headers = [
                (name, value)
                for (name, value) in response.raw.headers.items()
                if name.lower() not in excluded_headers
            ]

            app.logger.debug(f"Response headers to client: {response_headers}")
            app.logger.debug(f"Response status code: {response.status_code}")

            return Response(generate(), response.status_code, response_headers)

    except Exception as e:
        exception_type = type(e).__name__
        statsd.increment(
            "forwardarr.exception.count",
            tags=[f"indexer:{indexer_name}", f"exception_type:{exception_type}"],
        )
        app.logger.error(
            f"Unhandled exception for indexer '{indexer_name}': {e}\n{traceback.format_exc()}"
        )
        return Response("Internal server error.", status=500)

# API route
@app.route("/<indexer_name>/api", methods=["GET"])
def api_proxy(indexer_name):
    return handle_request(indexer_name, request_type="api")


# RSS route
@app.route("/<indexer_name>/rss", methods=["GET"])
def rss_proxy(indexer_name):
    return handle_request(indexer_name, request_type="rss")


# NZB get route
@app.route("/<indexer_name>/get", methods=["GET"])
def get_nzb(indexer_name):
    return handle_request(indexer_name, request_type="api")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
