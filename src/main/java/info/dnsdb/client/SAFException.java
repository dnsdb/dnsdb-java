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

/**
 * Exception raised when the DNSDB server reports a warning or failure via SAF.
 *
 * @author Farsight Security, Inc. &lt;support@farsightsecurity.com&gt;
 * @see <a href="https://docs.dnsdb.info/">Farsight DNSDB API Documentation.</a>
 * @see <a href="https://docs.dnsdb.info/dnsdb-saf-protocol/">Farsight Streaming API Framing Protocol.</a>
 */
public class SAFException extends DNSDBException {
    /**
     * Class constructor with a cause.
     *
     * @param cause Cause to pass to RuntimeException.
     */
    public SAFException(Throwable cause) {
        super(cause);
    }

    /**
     * Class constructor with a message.
     *
     * @param message Message to pass to RuntimeException.
     */
    public SAFException(String message) {
        super(message);
    }
}
