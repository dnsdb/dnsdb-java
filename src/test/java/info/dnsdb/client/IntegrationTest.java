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
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.Iterator;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

class IntegrationTest {
    static String apikey = System.getenv("APIKEY");

    @BeforeAll
    static void checkAPIKey() {
        assumeFalse(apikey == null || apikey.equals(""), "APIKEY environment variable set");
    }

    @Test
    void ping() {
        Client c = new HTTPClient(apikey);
        assertTrue(c.ping(), "Ping successful");
    }

    @Test
    void lookupRRSet() {
        Client c = new HTTPClient(apikey);

        Iterator<JSONObject> it = c.lookupRRSet(HTTPClient.TYPE_NAME, "*.fsi.io").rrtype("A").limit(5).stream();
        assertThrows(QueryLimitedException.class, () -> {
            while (it.hasNext()) {
                it.next();
            }
        });
    }

    @Test
    void lookupRDataName() {
        Client c = new HTTPClient(apikey);

        Iterator<JSONObject> it = c.lookupRData(HTTPClient.TYPE_NAME, "*.fsi.io").limit(5).stream();
        assertThrows(QueryLimitedException.class, () -> {
            while (it.hasNext()) {
                it.next();
            }
        });
    }

    @Test
    void lookupRDataIP() {
        Client c = new HTTPClient(apikey);

        Iterator<JSONObject> it = c.lookupRData(HTTPClient.TYPE_IP, "104.244.13.0/24").limit(5).stream();
        assertThrows(QueryLimitedException.class, () -> {
            while (it.hasNext()) {
                it.next();
            }
        });
    }

    @Test
    void lookupRDataRaw() {
        Client c = new HTTPClient(apikey);

        Iterator<JSONObject> it = c.lookupRData(HTTPClient.TYPE_RAW, "000A056C69737473106661727369676874736563757269747903636F6D00").limit(5).stream();
        assertTrue(it.hasNext());
        while (it.hasNext()) {
            it.next();
        }
    }

    @Test
    void flex() {
        Client c = new HTTPClient(apikey);

        Iterator<JSONObject> it = c.flex(HTTPClient.METHOD_REGEX, HTTPClient.KEY_RDATA, "farsightsecurity").disableLimitedException(true).limit(5).stream();
        assertTrue(it.hasNext());
        while (it.hasNext()) {
            it.next();
        }
    }
}