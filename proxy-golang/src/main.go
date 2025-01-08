package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/DataDog/datadog-go/v5/statsd"
	"github.com/gorilla/mux"
)

// -----------------------------------------------------------------------------
// Structs for JSON config
// -----------------------------------------------------------------------------

type IndexerConfig struct {
	URL      string `json:"url"`
	APIPath  string `json:"api_path,omitempty"`
	RSSPath  string `json:"rss_path,omitempty"`
	GetPath  string `json:"get_path,omitempty"`
	APIParam string `json:"api_param,omitempty"`
	Timeout  int    `json:"timeout,omitempty"`
	// You may want to store additional fields or dynamically parse "extra_params"
	// from your JSON. Adjust as needed.
}

type APIKeysConfig map[string]map[string]any

// Example shape:
// {
//   "<client_apikey>": {
//     "user": "<username>",
//     "<indexer_name>": {
//       "key": "actual-indexer-apikey",
//       "extra_params": {
//          "foo": "bar"
//       }
//     }
//   },
//   ...
// }

type ParameterConfig struct {
	API map[string]string `json:"api"` // param -> type ("string" or "int")
	RSS map[string]string `json:"rss"` // param -> type
}

// Global (for simplicity in a single-file sample)
var (
	indexerNameMap  map[string]IndexerConfig
	clientAPIKeyMap APIKeysConfig
	paramConfig     ParameterConfig

	indexerNamePattern = regexp.MustCompile(`^\w+$`)

	// Usually we'd define these via environment variables (DD_AGENT_HOST, etc.)
	statsdClient *statsd.Client
)

// -----------------------------------------------------------------------------
// Initialization
// -----------------------------------------------------------------------------

func init() {
	// Read environment variables or use defaults
	indexerUrlsJson := getEnv("INDEXER_URLS_JSON", "/config/indexer_config.json")
	apiKeysFile := getEnv("API_KEYS_FILE", "/config/api_keys.json")
	paramsFile := getEnv("PARAMETERS_CONFIG_FILE", "/config/parameters.json")

	// Load configs
	var err error
	indexerNameMap, err = loadIndexerConfig(indexerUrlsJson)
	if err != nil {
		log.Fatalf("Failed loading indexer config %s: %v", indexerUrlsJson, err)
	}
	log.Printf("Loaded %d indexers.\n", len(indexerNameMap))

	clientAPIKeyMap, err = loadAPIKeys(apiKeysFile)
	if err != nil {
		log.Fatalf("Failed loading API keys %s: %v", apiKeysFile, err)
	}
	log.Printf("Loaded %d client API keys.\n", len(clientAPIKeyMap))

	paramConfig, err = loadParameters(paramsFile)
	if err != nil {
		log.Printf("Warning: failed to load parameters config %s: %v (continuing)\n", paramsFile, err)
		// if not found or parse error, we keep going with empty config
	}

	// Initialize the Datadog statsd client
	ddAgentHost := getEnv("DD_AGENT_HOST", "localhost")
	ddAgentPort := getEnv("DD_DOGSTATSD_PORT", "8125")
	ddURL := fmt.Sprintf("%s:%s", ddAgentHost, ddAgentPort)
	statsdClient, err = statsd.New(ddURL)
	if err != nil {
		log.Printf("Warning: unable to connect to Datadog at %s: %v\n", ddURL, err)
	} else {
		log.Printf("Datadog statsd client initialized at %s.\n", ddURL)
	}
}

// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------

func main() {
	r := mux.NewRouter()
	log.Printf("Starting ForwardArr proxy server\n")

	r.HandleFunc("/{indexer_name}/api", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Handling API request\n")
		handleProxyRequest(w, r, "api")
	}).Methods("GET")

	r.HandleFunc("/{indexer_name}/rss", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Handling RSS request\n")
		handleProxyRequest(w, r, "rss")
	}).Methods("GET")

	// If `/get` is just an alias for the same logic as "api" (like in your Python script),
	// we’ll do the same:
	r.HandleFunc("/{indexer_name}/get", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Handling GET request\n")
		handleProxyRequest(w, r, "api")
	}).Methods("GET")

	// Start server
	addr := ":8080"
	log.Printf("Listening on %s\n", addr)
	if err := http.ListenAndServe(addr, r); err != nil {
		log.Fatal(err)
	}
}

// -----------------------------------------------------------------------------
// Core request handling
// -----------------------------------------------------------------------------

func handleProxyRequest(w http.ResponseWriter, r *http.Request, requestType string) {
	startTime := time.Now()

	vars := mux.Vars(r)
	indexerName := vars["indexer_name"]
	log.Printf("Handling request for indexer: %s\n", indexerName)

	incrementStat("forwardarr."+requestType+"_request.count", []string{"indexer:" + indexerName})

	// Validate indexer
	if !indexerNamePattern.MatchString(indexerName) {
		log.Printf("Invalid indexer name format: %s\n", indexerName)
		http.Error(w, "Invalid indexer name format.", http.StatusBadRequest)
		return
	}

	indexerInfo, ok := indexerNameMap[indexerName]
	if !ok {
		log.Printf("Indexer '%s' not found.\n", indexerName)
		http.Error(w, fmt.Sprintf("Indexer '%s' not found.", indexerName), http.StatusNotFound)
		return
	}

	usenetServerURL := indexerInfo.URL
	if usenetServerURL == "" {
		log.Printf("Indexer '%s' missing 'url' config.\n", indexerName)
		http.Error(w, "Indexer missing 'url' config.", http.StatusInternalServerError)
		return
	}

	// Custom "apikey" parameter name
	userIDParam := indexerInfo.APIParam
	if userIDParam == "" {
		userIDParam = "apikey"
	}

	// Timeout
	timeoutSeconds := indexerInfo.Timeout
	if timeoutSeconds == 0 {
		timeoutSeconds = 60
	}
	// Which path to call
	var usenetPath string
	switch requestType {
	case "rss":
		usenetPath = indexerInfo.RSSPath
		if usenetPath == "" {
			usenetPath = "/rss"
		}
	case "api":
		usenetPath = indexerInfo.APIPath
		if usenetPath == "" {
			usenetPath = "/api"
		}
	default:
		usenetPath = "/"
	}

	// Determine allowed parameters from config
	var allowedParams map[string]string
	switch requestType {
	case "rss":
		allowedParams = paramConfig.RSS
	default:
		// treat "api" or "get" as paramConfig.API
		allowedParams = paramConfig.API
	}

	// Validate and parse query params
	validated, err := validateAndParseParams(r.URL.Query(), allowedParams, requestType)
	if err != nil {
		incrementStat("forwardarr.validation_error", []string{"indexer:" + indexerName})
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Grab the user’s client-apikey
	clientAPIKey, hasAPIKey := validated["apikey"]
	if !hasAPIKey {
		http.Error(w, "API key is required.", http.StatusBadRequest)
		return
	}
	log.Printf("Client API key: %s\n", clientAPIKey)
	_ = validated // at this point validated includes "apikey" among others

	// Look up the mapping for that client key
	clientKeyEntry, ok := clientAPIKeyMap[clientAPIKey]
	if !ok {
		incrementStat("forwardarr.invalid_client_api_key", []string{"indexer:" + indexerName})
		http.Error(w, "Invalid API key.", http.StatusForbidden)
		return
	}
	log.Printf("Client API key found.\n")

	userNameAny, hasUser := clientKeyEntry["user"]
	userName := ""
	if hasUser {
		userName, _ = userNameAny.(string)
	}

	incrementStat("forwardarr.request.per_api_key", []string{"indexer:" + indexerName})
	if userName != "" {
		incrementStat("forwardarr.request.per_user", []string{"user:" + userName})
	}

	// Check if user is allowed for this indexer
	indexerValAny, hasIndexerVal := clientKeyEntry[indexerName]
	if !hasIndexerVal {
		incrementStat("forwardarr.access_denied", []string{"indexer:" + indexerName, "user:" + userName})
		http.Error(w, "Access denied for this indexer.", http.StatusForbidden)
		return
	}

	indexerValMap, _ := indexerValAny.(map[string]any)
	actualIndexerKeyAny, hasActualIndexerKey := indexerValMap["key"]
	if !hasActualIndexerKey {
		http.Error(w, "No upstream indexer key found.", http.StatusForbidden)
		return
	}
	actualIndexerKey, _ := actualIndexerKeyAny.(string)

	// Possibly add "extra_params"
	if extra, ok := indexerValMap["extra_params"]; ok {
		if extraMap, ok2 := extra.(map[string]any); ok2 {
			for k, v := range extraMap {
				validated[k] = fmt.Sprintf("%v", v)
			}
		}
	}

	// Log a hashed version of the client API key
	hashVal := sha256.Sum256([]byte(clientAPIKey))
	clientAPIKeyHashShort := hex.EncodeToString(hashVal[:])[:8]

	log.Printf("Client API Key Hash: %s\n", clientAPIKeyHashShort)
	log.Printf("Client Name: %s\n", userName)
	log.Printf("Indexer Name: %s\n", indexerName)
	log.Printf("Actual API Key Present? %t\n", (actualIndexerKey != ""))
	log.Printf("Connecting to %s%s\n", usenetServerURL, usenetPath)

	// Check if this is a "grab" (i.e., &t=get)
	isGrab := (validated["t"] == "get")
	if isGrab {
		incrementStat("forwardarr.request.grab", []string{"indexer:" + indexerName, "user:" + userName})
		log.Printf("Grab request detected.\n")
	}

	// Prepare final query to upstream
	indexerQuery := make(url.Values)
	for k, v := range validated {
		indexerQuery.Set(k, v)
	}
	// Replace the "apikey" with the upstream indexer key if the indexer uses a param named "apikey"
	if userIDParam == "apikey" {
		indexerQuery.Set("apikey", actualIndexerKey)
	} else {
		// Otherwise, add userIDParam as the actual key
		indexerQuery.Set(userIDParam, actualIndexerKey)
		indexerQuery.Del("apikey") // maybe remove the original param
	}

	// Make the upstream request
	client := http.Client{
		Timeout: time.Duration(timeoutSeconds) * time.Second,
	}

	upstreamStart := time.Now()

	incrementStat("forwardarr.upstream.request.count", []string{"indexer:" + indexerName, "user:" + userName})

	reqURL := fmt.Sprintf("%s%s?%s", usenetServerURL, usenetPath, indexerQuery.Encode())
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		incrementStat("forwardarr.upstream.error", []string{"indexer:" + indexerName})
		log.Printf("Failed building request: %v\n", err)
		http.Error(w, "Error contacting the indexer.", http.StatusBadGateway)
		return
	}

	req.Header.Set("Accept-Encoding", "gzip, deflate")
	userAgent := r.Header.Get("User-Agent")
	if userAgent == "" {
		userAgent = "ForwardArr Proxy (Go)"
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, http.ErrHandlerTimeout) {
			incrementStat("forwardarr.upstream.timeout", []string{"indexer:" + indexerName})
			log.Printf("Timeout contacting indexer %s\n", indexerName)
			http.Error(w, "Indexing server timed out.", http.StatusGatewayTimeout)
			return
		}
		incrementStat("forwardarr.upstream.connection_error", []string{"indexer:" + indexerName})
		log.Printf("Error contacting indexer %s: %v\n", indexerName, err)
		http.Error(w, "Error contacting the indexer.", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	upstreamDur := time.Since(upstreamStart)
	timingStat("forwardarr.upstream.response.time", upstreamDur, []string{"indexer:" + indexerName})

	fullDur := time.Since(startTime)
	timingStat("forwardarr.response.time", fullDur, []string{"indexer:" + indexerName})

	incrementStat("forwardarr.response.status_code", []string{
		"status_code:" + strconv.Itoa(resp.StatusCode),
		"indexer:" + indexerName,
	})

	// Content type + size metrics
	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "unknown"
	}
	incrementStat("forwardarr.response.content_type", []string{
		"content_type:" + contentType,
		"indexer:" + indexerName,
	})

	contentLenStr := resp.Header.Get("Content-Length")
	contentLen, _ := strconv.Atoi(contentLenStr)
	histogramStat("forwardarr.response.size", float64(contentLen), []string{"indexer:" + indexerName})

	// Slow request threshold
	if fullDur > (2 * time.Second) {
		incrementStat("forwardarr.slow_request", []string{"indexer:" + indexerName})
	}
	// 4xx or 5xx stats
	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		incrementStat("forwardarr.client_error", []string{
			"status_code:" + strconv.Itoa(resp.StatusCode),
			"indexer:" + indexerName,
		})
	} else if resp.StatusCode >= 500 && resp.StatusCode < 600 {
		incrementStat("forwardarr.server_error", []string{
			"status_code:" + strconv.Itoa(resp.StatusCode),
			"indexer:" + indexerName,
		})
	}

	// Stream back to client
	// For a "grab" we enforce Content-Type: application/x-nzb, plus Content-Disposition
	if isGrab {
		w.Header().Set("Content-Type", "application/x-nzb")
		// If the indexer gave a Content-Disposition, pass that along
		if disp := resp.Header.Get("Content-Disposition"); disp != "" {
			w.Header().Set("Content-Disposition", disp)
		} else {
			w.Header().Set("Content-Disposition", `attachment; filename="download.nzb"`)
		}
		// Stream the body
		w.WriteHeader(resp.StatusCode)
		if _, err := io.Copy(w, resp.Body); err != nil {
			log.Printf("Error streaming NZB body: %v\n", err)
		}
	} else {
		// Forward all headers except those that conflict
		for name, vals := range resp.Header {
			nameLower := strings.ToLower(name)
			switch nameLower {
			case "content-length", "transfer-encoding", "connection":
				continue
			default:
				for _, v := range vals {
					w.Header().Add(name, v)
				}
			}
		}
		w.WriteHeader(resp.StatusCode)

		if _, err := io.Copy(w, resp.Body); err != nil {
			log.Printf("Error streaming response: %v\n", err)
		}
	}
}

// -----------------------------------------------------------------------------
// Parameter validation logic
// -----------------------------------------------------------------------------

func validateAndParseParams(query url.Values, allowed map[string]string, requestType string) (map[string]string, error) {
	validated := make(map[string]string)

	for param, values := range query {
		// If you have a finite set of allowed params, skip anything not in the list
		if len(allowed) > 0 {
			if _, found := allowed[param]; !found {
				log.Printf("Rejected parameter: %s\n", param)
				incrementStat("forwardarr.parameter.rejected", []string{"parameter:" + param})
				continue
			}
		}
		// If param is allowed or if you allow pass-through for param
		// parse type
		expectedType, haveType := allowed[param]
		if !haveType {
			// default to "string"
			expectedType = "string"
		}

		// For demonstration, let's do a *very basic* check
		if len(values) == 1 {
			cleanVal := strings.TrimSpace(values[0])
			if len(cleanVal) > 255 {
				return nil, fmt.Errorf("Parameter '%s' is too long.", param)
			}
			switch expectedType {
			case "int":
				if _, err := strconv.Atoi(cleanVal); err != nil {
					return nil, fmt.Errorf("Invalid value for param '%s'. Expected int. Request failed.", param)
				}
			case "string":
				// Optional: use regex checks if needed
			}
			validated[param] = cleanVal
			incrementStat("forwardarr.parameter.usage", []string{"parameter:" + param})
		} else {
			// If multiple values for the same param, you can handle them differently
			// For simplicity, just store the first or join them
			cleanVal := strings.Join(values, ",")
			validated[param] = cleanVal
			incrementStat("forwardarr.parameter.usage", []string{"parameter:" + param})
		}
	}

	return validated, nil
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func loadIndexerConfig(path string) (map[string]IndexerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := make(map[string]IndexerConfig)
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func loadAPIKeys(path string) (APIKeysConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := make(APIKeysConfig)
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func loadParameters(path string) (ParameterConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return ParameterConfig{}, err
	}
	var pc ParameterConfig
	if err := json.Unmarshal(data, &pc); err != nil {
		return ParameterConfig{}, err
	}
	return pc, nil
}

func incrementStat(name string, tags []string) {
	if statsdClient != nil {
		_ = statsdClient.Incr(name, tags, 1.0)
	}
}

func timingStat(name string, dur time.Duration, tags []string) {
	if statsdClient != nil {
		_ = statsdClient.Timing(name, dur, tags, 1.0)
	}
}

func histogramStat(name string, value float64, tags []string) {
	if statsdClient != nil {
		_ = statsdClient.Histogram(name, value, tags, 1.0)
	}
}

func getEnv(key, defVal string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return defVal
}
