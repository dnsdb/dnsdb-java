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

import org.apache.http.client.utils.URIBuilder;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;

import static java.net.HttpURLConnection.HTTP_OK;

/**
 * An object used for setting parameters and executing DNSDB Queries. This is written so that developers can use the
 * fluent API pattern, eg. query.rrtype("A").limit(5).stream()
 *
 * @author Farsight Security, Inc. &lt;support@farsightsecurity.com&gt;
 * @see <a href="https://docs.dnsdb.info/">Farsight DNSDB API Documentation.</a>
 */
public class Query {
    private static final String RRTYPE_ANY = "ANY";

    static final String COND_BEGIN = "begin";
    static final String COND_ONGOING = "ongoing";
    static final String COND_SUCCEEDED = "succeeded";
    static final String COND_LIMITED = "limited";
    static final String COND_FAILED = "failed";

    private static final String DEFAULT_SWCLIENT = "java";

    private final HTTPClient client;
    private final URIBuilder uriBuilder;
    private String rrtype;
    private String bailiwick;
    private boolean disableLimitedException;

    /**
     * Class constructor for Query. Sends requests to uri using credentials and HttpClient from client.
     * This is package scope because it really belongs to the implementation (HttpClient).
     *
     * @param client HttpClient object that initiated the query.
     * @param uri URI of the request. Path components for rrtype and bailiwick are appended as necessary.
     */
    Query(HTTPClient client, URI uri) {
        this.client = client;
        uriBuilder = new URIBuilder(uri);
        this.rrtype = RRTYPE_ANY;

        swClient(DEFAULT_SWCLIENT);
    }

    /**
     * Disable throwing of QueryLimitedException.
     *
     * @param ok True to disable throwing QueryLimitedException, false to enable.
     * @return The Query object for further use in the fluent API pattern.
     */
    public Query disableLimitedException(boolean ok) {
        this.disableLimitedException = ok;
        return this;
    }

    /**
     * Set the rrtype parameter of the query. This limits results to only that rrtype, or all rrtypes in the case of
     * RRTYPE_ANY.
     *
     * @param rrtype The rrtype to limit results to.
     * @return The Query object for further use in the fluent API pattern.
     */
    public Query rrtype(String rrtype) {
        this.rrtype = rrtype;
        return this;
    }

    /**
     * Set the bailiwick parameter of the query. This limits results to those returned by nameservers that are
     * authoritative to the specified bailiwick. For example: a bailiwick of com would only include results from
     * the GTLD servers.
     *
     * @param bailiwick The bailiwick to limit results to.
     * @return The Query object for further use in the fluent API pattern.
     * @see <a href="https://docs.dnsdb.info/dnsdb-apiv2/#rrset-lookups">rrset lookups.</a>
     */
    public Query bailiwick(String bailiwick) {
        this.bailiwick = bailiwick;
        return this;
    }

    /**
     * Provide results before the defined timestamp for when the DNS record was first observed.
     *
     * @param time Seconds since the epoch for an absolute timestamp, negative number for a relative timestamp.
     * @return The Query object for further use in the fluent API pattern.
     * @see <a href="https://docs.dnsdb.info/dnsdb-apiv2/#time-fencing-query-parameters">Time-fencing query parameters.</a>
     */
    public Query timeFirstBefore(int time) {
        uriBuilder.setParameter("time_first_before", Integer.toString(time));
        return this;
    }

    /**
     * Provide results before the defined timestamp for when the DNS record was first observed.
     *
     * @param date Date, truncated to seconds.
     * @return The Query object for further use in the fluent API pattern.
     * @see <a href="https://docs.dnsdb.info/dnsdb-apiv2/#time-fencing-query-parameters">Time-fencing query parameters.</a>
     */
    public Query timeFirstBefore(Date date) {
        uriBuilder.setParameter("time_first_before", Long.toString(date.getTime() / 1000));
        return this;
    }

    /**
     * Provide results before the defined timestamp for when the DNS record was first observed.
     *
     * @param instant Instant, truncated to seconds.
     * @return The Query object for further use in the fluent API pattern.
     * @see <a href="https://docs.dnsdb.info/dnsdb-apiv2/#time-fencing-query-parameters">Time-fencing query parameters.</a>
     */
    public Query timeFirstBefore(Instant instant) {
        uriBuilder.setParameter("time_first_before", Long.toString(instant.getEpochSecond()));
        return this;
    }

    /**
     * Provide results after the defined timestamp for when the DNS record was first observed.
     *
     * @param time Seconds since the epoch for an absolute timestamp, negative number for a relative timestamp.
     * @return The Query object for further use in the fluent API pattern.
     * @see <a href="https://docs.dnsdb.info/dnsdb-apiv2/#time-fencing-query-parameters">Time-fencing query parameters.</a>
     */
    public Query timeFirstAfter(int time) {
        uriBuilder.setParameter("time_first_after", Integer.toString(time));
        return this;
    }

    /**
     * Provide results after the defined timestamp for when the DNS record was first observed.
     *
     * @param date Date, truncated to seconds.
     * @return The Query object for further use in the fluent API pattern.
     * @see <a href="https://docs.dnsdb.info/dnsdb-apiv2/#time-fencing-query-parameters">Time-fencing query parameters.</a>
     */
    public Query timeFirstAfter(Date date) {
        uriBuilder.setParameter("time_first_after", Long.toString(date.getTime() / 1000));
        return this;
    }

    /**
     * Provide results after the defined timestamp for when the DNS record was first observed.
     *
     * @param instant Instant, truncated to seconds.
     * @return The Query object for further use in the fluent API pattern.
     * @see <a href="https://docs.dnsdb.info/dnsdb-apiv2/#time-fencing-query-parameters">Time-fencing query parameters.</a>
     */
    public Query timeFirstAfter(Instant instant) {
        uriBuilder.setParameter("time_first_after", Long.toString(instant.getEpochSecond()));
        return this;
    }

    /**
     * Provide results before the defined timestamp for when the DNS record was last observed.
     *
     * @param time Seconds since the epoch for an absolute timestamp, negative number for a relative timestamp.
     * @return The Query object for further use in the fluent API pattern.
     * @see <a href="https://docs.dnsdb.info/dnsdb-apiv2/#time-fencing-query-parameters">Time-fencing query parameters.</a>
     */
    public Query timeLastBefore(int time) {
        uriBuilder.setParameter("time_last_before", Integer.toString(time));
        return this;
    }

    /**
     * Provide results before the defined timestamp for when the DNS record was last observed.
     *
     * @param date Date, truncated to seconds.
     * @return The Query object for further use in the fluent API pattern.
     * @see <a href="https://docs.dnsdb.info/dnsdb-apiv2/#time-fencing-query-parameters">Time-fencing query parameters.</a>
     */
    public Query timeLastBefore(Date date) {
        uriBuilder.setParameter("time_last_before", Long.toString(date.getTime() / 1000));
        return this;
    }

    /**
     * Provide results before the defined timestamp for when the DNS record was last observed.
     *
     * @param instant Instant, truncated to seconds.
     * @return The Query object for further use in the fluent API pattern.
     * @see <a href="https://docs.dnsdb.info/dnsdb-apiv2/#time-fencing-query-parameters">Time-fencing query parameters.</a>
     */
    public Query timeLastBefore(Instant instant) {
        uriBuilder.setParameter("time_last_before", Long.toString(instant.getEpochSecond()));
        return this;
    }

    /**
     * Provide results after the defined timestamp for when the DNS record was last observed.
     *
     * @param time Seconds since the epoch for an absolute timestamp, negative number for a relative timestamp.
     * @return The Query object for further use in the fluent API pattern.
     * @see <a href="https://docs.dnsdb.info/dnsdb-apiv2/#time-fencing-query-parameters">Time-fencing query parameters.</a>
     */
    public Query timeLastAfter(int time) {
        uriBuilder.setParameter("time_last_after", Integer.toString(time));
        return this;
    }

    /**
     * Provide results after the defined timestamp for when the DNS record was last observed.
     *
     * @param date Date, truncated to seconds.
     * @return The Query object for further use in the fluent API pattern.
     * @see <a href="https://docs.dnsdb.info/dnsdb-apiv2/#time-fencing-query-parameters">Time-fencing query parameters.</a>
     */
    public Query timeLastAfter(Date date) {
        uriBuilder.setParameter("time_last_after", Long.toString(date.getTime() / 1000));
        return this;
    }

    /**
     * Provide results after the defined timestamp for when the DNS record was last observed.
     *
     * @param instant Instant, truncated to seconds.
     * @return The Query object for further use in the fluent API pattern.
     * @see <a href="https://docs.dnsdb.info/dnsdb-apiv2/#time-fencing-query-parameters">Time-fencing query parameters.</a>
     */
    public Query timeLastAfter(Instant instant) {
        uriBuilder.setParameter("time_last_after", Long.toString(instant.getEpochSecond()));
        return this;
    }

    /**
     * Limit for the number of results returned via these lookup methods. There is a built-in limit to the number of results that are returned via these lookup methods. The default limit is set at 10,000. This limit can be raised or lowered by setting the “limit” query parameter.
     *
     * There is also a maximum number of results allowed; requesting a limit greater than the maximum will only return the maximum. See results_max below for information on that maximum. If “?limit=0” is used then DNSDB will return the maximum number of results allowed. Obviously, if there are less results for the query than the requested limit, only the actual amount can be returned.
     *
     * @param limit Number of rows.
     * @return The Query object for further use in the fluent API pattern.
     * @see <a href="https://docs.dnsdb.info/dnsdb-apiv2/#other-query-parameters">Other query parameters.</a>
     */
    public Query limit(int limit) {
        uriBuilder.setParameter("limit", Integer.toString(limit));
        return this;
    }

    /**
     * Name of the API client software generating the DNSDB query. Limited to twenty alphanumeric characters. This may be logged by the DNSDB API server. Farsight support can help you debug a new API client using this and the following parameter.
     *
     * The default is "java".
     *
     * @param swclient Alphanumeric string to submit for swclient.
     * @return The Query object for further use in the fluent API pattern.
     * @see <a href="https://docs.dnsdb.info/dnsdb-apiv2/#other-query-parameters">Other query parameters.</a>
     */
    public Query swClient(String swclient) {
        uriBuilder.setParameter("swclient", swclient);
        return this;
    }

    /**
     * Version number of the API client software generating the DNSDB query. Limited to twenty alphanumeric characters plus dash, underscore, and period. This may be logged by the DNSDB API server.
     *
     * There is no default.
     *
     * @param version Alphanumeric version string to submit for version.
     * @return The Query object for further use in the fluent API pattern.
     * @see <a href="https://docs.dnsdb.info/dnsdb-apiv2/#other-query-parameters">Other query parameters.</a>
     */
    public Query version(String version) {
        uriBuilder.setParameter("version", version);
        return this;
    }

    /**
     * Client software specific identity of the user of the API client. Comprised of an alphanumeric string, a colon, and an alphanumeric string, limited to thirty characters. This may be logged by the DNSDB API server.
     *
     * There is no default.
     *
     * @param id Alphanumeric string with a colon to submit for id.
     * @return The Query object for further use in the fluent API pattern.
     * @see <a href="https://docs.dnsdb.info/dnsdb-apiv2/#other-query-parameters">Other query parameters.</a>
     */
    public Query id(String id) {
        uriBuilder.setParameter("id", id);
        return this;
    }

    /**
     * Aggregated results group identical rrsets across all time periods and is the classic behavior from querying the DNSDB. This means you could get the total number of times an rrset has been observed, but not when it was observed. Unaggregated results ungroup identical rrsets, allowing you to see how the domain name was resolved in the DNS across the full-time range covered in DNSDB (subject to time fencing). This can give a more accurate impression of record request volume across time because it will reveal the distinct timestamps of records whose values are repeated. You can answer questions like, “Was a domain parked for a long time, mostly unused, until it was repurposed for serving malware or relaying spam, but then was abandoned again?” It allows you to see if a record was observed heavily in the last week vs. having been observed constantly for years.
     *
     * @param on True to enable, false to disable.
     * @return The Query object for further use in the fluent API pattern.
     * @see <a href="https://docs.dnsdb.info/dnsdb-apiv2/#other-query-parameters">Other query parameters.</a>
     */
    public Query aggr(boolean on) {
        uriBuilder.setParameter("aggr", Boolean.toString(on));
        return this;
    }

    /**
     * A boolean value that is True if time values (in time_first, time_last, zone_time_first, zone_time_last) should be returned in human readable (RFC3339 compliant) format or False if Unix-style time values in seconds since the epoch should be returned. False is the classic behavior from querying the DNSDB and is the default value for this option.
     *
     * @param on True to enable, false to disable.
     * @return The Query object for further use in the fluent API pattern.
     * @see <a href="https://docs.dnsdb.info/dnsdb-apiv2/#other-query-parameters">Other query parameters.</a>
     */
    public Query humanTime(boolean on) {
        uriBuilder.setParameter("aggr", Boolean.toString(on));
        return this;
    }

    /**
     * How many rows to offset (e.g. skip) in the results. This implements an incremental result transfer feature, allowing you to view more of the available results for a single query. The rows are offset prior to the limit parameter being applied, therefore offset allows seeing additional results past a limit that matches the maximum number of results. Note that DNSDB recalculates the results for each query and the order of results might not be preserved. Therefore, this capability is not a valid way to walk all results over multiple queries – some results might be missing and some might be duplicated. The actual offset that can be used is limited or for certain API keys, offset is not allowed – see the offset_max rate_limit key below.
     *
     * The offset value must be a positive integer.
     *
     * The default is 0, which means do not offset the rows.
     *
     * @param offset How many rows to offset (e.g. skip) in the results.
     * @return The Query object for further use in the fluent API pattern.
     * @see <a href="https://docs.dnsdb.info/dnsdb-apiv2/#additional-query-parameter-for-lookup">Additional query parameter for lookup.</a>
     */
    public Query offset(int offset) {
        uriBuilder.setParameter("offset", Integer.toString(offset));
        return this;
    }

    /**
     * max_count controls stopping when we reach that summary count. The resulting total count can exceed max_count as it will include the entire count from the last rrset examined.
     *
     * The default is to not constrain the count.
     *
     * @param maxCount Count at which to stop summarizing.
     * @return The Query object for further use in the fluent API pattern.
     * @see <a href="https://docs.dnsdb.info/dnsdb-apiv2/#additional-query-parameter-for-summarize">Additional query parameter for summarize.</a>
     */
    public Query maxCount(int maxCount) {
        uriBuilder.setParameter("max_count", Integer.toString(maxCount));
        return this;
    }

    /**
     * The &quot;exclude&quot; parameter is used to exclude (i.e. filter-out) results that match. Conceptually, this is like the shell pipeline: egrep $VALUE &lt;DNSDB | egrep -v $exclude. Its value is a regular expression or glob, depending upon the search_method.
     *
     * @param exclude A glob or regular expression.
     * @return The Query object for further use in the fluent API pattern.
     * @see <a href="https://docs.dnsdb.info/dnsdb-flex-api/#optional-query-parameters">Optional query parameters for Flexible Search.</a>
     * @see <a href="https://docs.dnsdb.info/dnsdb-flex-api/#the-exclude-parameter">The exclude parameter.</a>
     */
    public Query exclude(String exclude) {
        uriBuilder.setParameter("exclude", exclude);
        return this;
    }

    /**
     * Execute the query, returning an Iterator of results. The Iterator will throw the same exceptions
     * listed below on calls to next() and hasNext().
     *
     * @return An Iterator of JSON objects formatted per the query endpoint used.
     * @throws DNSDBException If the server returns an invalid status code.
     * @throws DNSDBException If the connection was unsuccessful.
     * @throws InvalidJSONException If invalid JSON data is returned by the server.
     * @throws TruncatedResponseException If the response does not include a trailer or is otherwise truncated.
     * @throws UnexpectedCondException If the server sends an unknown condition or a condition at the wrong state.
     * @throws QueryLimitedException If the server reports that the result set was incomplete.
     * @throws QueryFailedException If the server reports that the query has failed.
     * @see <a href="https://docs.dnsdb.info/dnsdb-apiv2/#rrset-results">rrset results for lookup.</a>
     * @see <a href="https://docs.dnsdb.info/dnsdb-apiv2/#rdata-results">rdata results for lookup.</a>
     * @see <a href="https://docs.dnsdb.info/dnsdb-flex-api/#rrnames-results">rrnames results for flex.</a>
     * @see <a href="https://docs.dnsdb.info/dnsdb-flex-api/#rdata-results">rdata results for flex.</a>
     */
    public Iterator<JSONObject> stream() {
        URI uri;

        List<String> pathSegments = uriBuilder.getPathSegments();
        pathSegments.add(rrtype);
        if (bailiwick != null) {
            pathSegments.add(bailiwick);
        }
        uriBuilder.setPathSegments(pathSegments);

        try {
            uri = uriBuilder.build();
        } catch (URISyntaxException e) {
            throw new DNSDBException(e);
        }

        HttpRequest request = client.buildRequest(uri);
        HttpResponse<InputStream> response;
        try {
            response = this.client.client.send(request, HttpResponse.BodyHandlers.ofInputStream());
            if (response.statusCode() != HTTP_OK) {
                throw new DNSDBException("Received status code " + response.statusCode());
            }
        } catch (IOException | InterruptedException e) {
            throw new DNSDBException(e);
        }

        BufferedReader reader = new BufferedReader(new InputStreamReader(response.body()));

        JSONObject line;
        try {
            line = new JSONObject(reader.readLine());
        } catch (IOException e) {
            throw new TruncatedResponseException(e);
        } catch (JSONException e) {
            throw new DNSDBException(e);
        }
        if (!line.getString("cond").equals(COND_BEGIN)) {
            throw new UnexpectedCondException(line);
        }

        return new Iterator<>() {
            boolean done;
            JSONObject next;

            @Override
            public boolean hasNext() {
                getNext();
                return !done;
            }

            @Override
            public JSONObject next() {
                getNext();
                if (next == null) {
                    throw new NoSuchElementException();
                }
                JSONObject res = next;
                next = null;
                return res;
            }

            private void getNext() {
                if (next != null) {
                    return;
                }

                while (true) {
                    JSONObject line;
                    try {
                        line = new JSONObject(reader.readLine());
                    } catch (IOException e) {
                        throw new TruncatedResponseException(e);
                    } catch (JSONException e) {
                        throw new DNSDBException(e);
                    }

                    String cond = "";
                    if (line.has("cond")) {
                        cond = line.getString("cond");
                    }

                    switch (cond) {
                        case "":
                        case COND_ONGOING:
                            if (line.has("obj")) {
                                next = line.getJSONObject("obj");
                                return;
                            }
                            break;
                        case COND_SUCCEEDED:
                            done = true;
                            return;
                        case COND_FAILED:
                            throw new QueryFailedException(line);
                        case COND_LIMITED:
                            if (disableLimitedException) {
                                done = true;
                                return;
                            }
                            throw new QueryLimitedException();
                        default:
                            throw new UnexpectedCondException(line);
                    }
                }
            }
        };
    }
}
