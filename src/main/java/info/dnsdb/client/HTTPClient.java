// Copyright (c) 2021 by Farsight Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package info.dnsdb.client;


import org.json.JSONObject;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static java.net.HttpURLConnection.HTTP_OK;

/**
 * Implementation of a DNSDB 2.0 with Flexible Search client.
 *
 * @author Farsight Security, Inc. &lt;support@farsightsecurity.com&gt;
 * @see <a href="https://docs.dnsdb.info/">Farsight DNSDB API Documentation.</a>
 */
public class HTTPClient implements Client {
    /**
     * The default server for the DNSDB API.
     */
    public static final String DEFAULT_SERVER = "https://api.dnsdb.info";
    private static final String PREFIX = "/dnsdb/v2/";
    private static final String X_API_KEY = "X-API-Key";
    private static final String ACCEPT = "Accept";
    private static final String CONTENT_TYPE = "application/x-ndjson";

    private final String apikey;
    private final String server;
    final HttpClient client;

    /**
     * Class constructor specifying an API key and using the default server and HTTP client.
     *
     * @param apikey Access token for the DNSDB service.
     */
    public HTTPClient(String apikey) {
        this(apikey, DEFAULT_SERVER);
    }

    /**
     * Class constructor specifying an API key and an alternate server URI.
     *
     * @param apikey Access token for the DNSDB service.
     * @param server Base URI for the DNSDB server.
     */
    public HTTPClient(String apikey, String server) {
        this(apikey, server, java.net.http.HttpClient.newHttpClient());
    }

    /**
     * Class constructor specifying an API key, an alternate server URI, and a specific HttpClient. One may
     * want to override the latter if testing, or for network environments requiring proxies.
     *
     * @param apikey Access token for the DNSDB service.
     * @param server Base URI for the DNSDB server.
     * @param client HttpClient used for connections to the DNSDB server.
     */
    public HTTPClient(String apikey, String server, HttpClient client) {
        this.apikey = apikey;
        this.server = server;
        this.client = client;
    }

    /**
     * Calls the DNSDB ping endpoint to verify end-to-end connectivity, but not apikey validity.
     *
     * @return True if the client can connect to the DNSDB API server and the ping endpoint executes successfully, false otherwise.
     * @see <a href="https://docs.dnsdb.info/dnsdb-apiv2/#ping-requests">Documentation for the ping endpoint.</a>
     * @see Client#rateLimit() if you need to test your apikey.
     */
    @Override
    public boolean ping() {
        HttpRequest request = buildRequest(buildURI("ping"));
        try {
            HttpResponse<String> response = this.client.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != HTTP_OK) {
                return false;
            }

            JSONObject json = new JSONObject(response.body());
            return json.get("ping").equals("ok");

        } catch (IOException | InterruptedException e) {
            return false;
        }
    }

    /**
     * Calls the DNSDB rate_limit endpoint to obtain information about service limits.
     *
     * @return Returns a JSONObject corresponding to the output format of the DNSDB rate_limit endpoint.
     * @see <a href="https://docs.dnsdb.info/dnsdb-apiv2/#service-limits-and-quotas">Documentation for the service limits API and output format.</a>
     * @throws DNSDBException If the connection fails or a non-OK (200) status code is returned.
     */
    @Override
    public JSONObject rateLimit() {
        HttpRequest request = buildRequest(buildURI("ping"));
        try {
            HttpResponse<String> response = this.client.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != HTTP_OK) {
                throw new DNSDBException(String.format("rate_limit failed: status code %d", response.statusCode()));
            }

            JSONObject json = new JSONObject(response.body());
            return json;

        } catch (IOException | InterruptedException e) {
            throw new DNSDBException(e);
        }
    }

    /**
     * Creates a Query object for a lookup RRSet search of type name or raw for the given value.
     *
     * @param type One of TYPE_NAME or TYPE_IP.
     * @param value A domain name with or without wildcards or a hex-encoded raw rrname string.
     * @return A Query object set up with the desired parameters.
     * @see <a href="https://docs.dnsdb.info/dnsdb-apiv2/#rrset-lookups">Documentation for rrset lookups.</a>
     */
    @Override
    public Query lookupRRSet(String type, String value) {
        return new Query(this, buildURI(String.format("lookup/rrset/%s/%s", type, value)));
    }

    /**
     * Creates a Query object for a lookup RData search of type name, ip, or raw for the given value.
     *
     * @param type One of TYPE_NAME, TYPE_IP, or TYPE_RAW.
     * @param value A domain name with or without wildcards, an IP address with or without CIDR notation, or a hex-encoded raw rrname string.
     * @return A Query object set up with the desired parameters.
     * @see <a href="https://docs.dnsdb.info/dnsdb-apiv2/#rdata-lookups">Documentation for rdata lookups.</a>
     */
    @Override
    public Query lookupRData(String type, String value) {
        if (type.equals(TYPE_IP)) {
            value = value.replace("/", ",");
        }
        return new Query(this, buildURI(String.format("lookup/rdata/%s/%s", type, value)));
    }

    /**
     * Creates a Query object for a flexible search of method regex or glob, key of rrnames or rdata, for the given value.
     *
     * @param method One of METHOD_REGEX or METHOD_GLOB.
     * @param key One of KEY_RRNAMES or KEY_RDATA.
     * @param value A regular expression or glob to search for.
     * @return A Query object set up with the desired parameters.
     * @see <a href="https://docs.dnsdb.info/dnsdb-flex-reference-guide/">Flexible Search Reference Guide.</a>
     * @see <a href="https://docs.dnsdb.info/dnsdb-flex-api/">Flexible Search API Programmers Guide.</a>
     * @see <a href="https://docs.dnsdb.info/dnsdb-fcre-reference-guide/">DNSDB FCRE Reference Guide.</a>
     * @see <a href="https://docs.dnsdb.info/dnsdb-glob-reference-guide/">DNSDB Glob Reference Guide.</a>
     */
    @Override
    public Query flex(String method, String key, String value) {
        return new Query(this, buildURI(String.format("%s/%s/%s", method, key, value)));
    }

    URI buildURI(String suffix) {
        URI uri;
        try {
            uri = new URI(this.server + PREFIX + suffix);
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
        return uri;
    }

    HttpRequest buildRequest(URI uri) {
        return HttpRequest.newBuilder(uri).GET()
                .header(HTTPClient.X_API_KEY, this.apikey).header(ACCEPT, CONTENT_TYPE).build();
    }
}
