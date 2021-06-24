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
 * Exception raised when the DNSDB server reports via SAF that a query has failed.
 *
 * @author Farsight Security, Inc. &lt;support@farsightsecurity.com&gt;
 * @see <a href="https://docs.dnsdb.info/">Farsight DNSDB API Documentation.</a>
 * @see <a href="https://docs.dnsdb.info/dnsdb-saf-protocol/">Farsight Streaming API Framing Protocol.</a>
 */
public class QueryFailedException extends SAFException {
    /**
     * Class constructor using a parsed SAF message.
     * @param obj JSONObject with optional cond and msg keys.
     */
    public QueryFailedException(JSONObject obj) {
        super(format(obj));
    }

    private static String format(JSONObject obj) {
        String cond = Query.COND_ONGOING;
        if (obj.has("cond")) {
            cond = obj.getString("cond");
        }

        if (obj.has("msg")) {
            String msg = obj.getString("msg");
            return String.format("Query failed: %s: %s", cond, msg);
        }

        return String.format("Query failed: %s", cond);
    }
}
