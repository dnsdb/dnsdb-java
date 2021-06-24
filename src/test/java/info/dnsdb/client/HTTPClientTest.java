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

import org.junit.jupiter.api.Test;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpRequest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

class HTTPClientTest {
    @Test
    public void buildURI() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        Client c = new HTTPClient("abc123");
        Method buildRequest = c.getClass().getDeclaredMethod("buildURI", String.class);
        buildRequest.setAccessible(true);

        URI uri = (URI) buildRequest.invoke(c, "test");
        assertEquals(uri.getScheme(), "https");
        assertEquals(uri.getHost(), "api.dnsdb.info");
        assertEquals(uri.getPath(), "/dnsdb/v2/test");
    }

    @Test
    public void buildRequest() throws NoSuchMethodException, URISyntaxException, InvocationTargetException, IllegalAccessException {
        Client c = new HTTPClient("abc123");
        Method buildRequest = c.getClass().getDeclaredMethod("buildRequest", URI.class);
        buildRequest.setAccessible(true);

        URI uri = new URI("https://test");
        HttpRequest req = (HttpRequest) buildRequest.invoke(c, uri);
        assertNotEquals(req.headers().firstValue("X-API-Key"), "", "X-API-Key header set");
        assertNotEquals(req.headers().firstValue("Accept"), "", "Accept header set");
    }
}