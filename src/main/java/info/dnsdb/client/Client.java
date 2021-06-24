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

/**
 * Interface for a DNSDB 2.0 with Flexible Search client. We provide this so that implementors can mock a Client for
 * unit testing.
 *
 * @author Farsight Security, Inc. &lt;support@farsightsecurity.com&gt;
 * @see <a href="https://docs.dnsdb.info/">Farsight DNSDB API Documentation.</a>
 */
public interface Client {
    /**
     * Calls the DNSDB ping endpoint to verify end-to-end connectivity, but not apikey validity.
     *
     * @return True if the client can connect to the DNSDB API server and the ping endpoint executes successfully, false otherwise.
     * @see <a href="https://docs.dnsdb.info/dnsdb-apiv2/#ping-requests">Documentation for the ping endpoint.</a>
     * @see Client#rateLimit() if you need to test your apikey.
     */
    boolean ping();

    /**
     * Calls the DNSDB rate_limit endpoint to obtain information about service limits.
     *
     * @return Returns a JSONObject corresponding to the output format of the DNSDB rate_limit endpoint.
     * @see <a href="https://docs.dnsdb.info/dnsdb-apiv2/#service-limits-and-quotas">Documentation for the service limits API and output format.</a>
     */
    JSONObject rateLimit();

    /**
     * Type for name queries.
     */
    String TYPE_NAME = "name";

    /**
     * Type for IP and CIDR queries. RData only.
     */
    String TYPE_IP = "ip";

    /**
     * Type for raw queries.
     */
    String TYPE_RAW = "raw";

    /**
     * Creates a Query object for a lookup RRSet search of type name or raw for the given value.
     *
     * @param type One of TYPE_NAME or TYPE_IP.
     * @param value A domain name with or without wildcards or a hex-encoded raw rrname string.
     * @return A Query object set up with the desired parameters.
     * @see <a href="https://docs.dnsdb.info/dnsdb-apiv2/#rrset-lookups">Documentation for rrset lookups.</a>
     */
    Query lookupRRSet(String type, String value);

    /**
     * Creates a Query object for a lookup RData search of type name, ip, or raw for the given value.
     *
     * @param type One of TYPE_NAME, TYPE_IP, or TYPE_RAW.
     * @param value A domain name with or without wildcards, an IP address with or without CIDR notation, or a hex-encoded raw rrname string.
     * @return A Query object set up with the desired parameters.
     * @see <a href="https://docs.dnsdb.info/dnsdb-apiv2/#rdata-lookups">Documentation for rdata lookups.</a>
     */
    Query lookupRData(String type, String value);

    /**
     * Method for regex flex queries.
     */
    String METHOD_REGEX = "regex";

    /**
     * Method for glob flex queries.
     */
    String METHOD_GLOB = "glob";

    /**
     * Key for rrnames flex queries.
     */
    String KEY_RRNAMES = "rrnames";

    /**
     * Key for rdata flex queries.
     */
    String KEY_RDATA = "rdata";

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
    Query flex(String method, String key, String value);
}
