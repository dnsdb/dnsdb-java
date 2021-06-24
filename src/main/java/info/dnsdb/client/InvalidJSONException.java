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

import org.json.JSONException;

/**
 * Exception raised if JSON data fails to decode.
 *
 * @author Farsight Security, Inc. &lt;support@farsightsecurity.com&gt;
 * @see <a href="https://docs.dnsdb.info/">Farsight DNSDB API Documentation.</a>
 */
public class InvalidJSONException extends DNSDBException {
    /**
     * Class constructor with cause.
     *
     * @param cause A JSONException that was the cause of this exception.
     */
    public InvalidJSONException(JSONException cause) {
        super(cause);
    }
}
