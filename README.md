# Farsight DNSDB Version 2 with Flexible Search SDK for Java

[Farsight Security DNSDB®](https://www.farsightsecurity.com/solutions/dnsdb/) is the world’s largest DNS intelligence database that provides a unique, fact-based, multifaceted view of the configuration of the global Internet infrastructure. DNSDB leverages the richness of Farsight’s Security Information Exchange (SIE) data-sharing platform and is engineered and operated by leading DNS experts. Farsight collects Passive DNS data from its global sensor array. It then filters and verifies the DNS transactions before inserting them into the DNSDB, along with ICANN-sponsored zone file access download data. The end result is the highest-quality and most comprehensive DNS intelligence data service of its kind - with more than 100 billion DNS records since 2010.

This software development kit for Java implements the [DNSDB Version 2](https://docs.dnsdb.info/dnsdb-apiv2/) with Flexible Search API. 

## Requirements

- Java 11 or greater.
- [Apache Maven](https://maven.apache.org/).

To purchase DNSDB, please complete the [application form](https://www.farsightsecurity.com/order-form/). Our due diligence process requires that you provide answers for all required fields in the application. We must be able to positively establish your identity and projected use case, so your cooperation in completing this information will be greatly appreciated and expedite the approval process. Once your application is completed, Farsight Security will review and respond to your request within two business days.

DNSDB Free 30-day Trial Key: Farsight’s [API Key portability program](https://www.farsightsecurity.com/trial-api/) lets you unlock the power of DNS intelligence across dozens of SIEM, Orchestration, Automation and Threat Intelligence Platforms that already support Farsight's DNSDB RESTful API. 

## Usage

Build the jar file with Maven. It will be located in the `target` directory.

```shell script
mvn package
```

Import the dnsdb library and configure a client.

```java
package example;

import info.dnsdb.client.Client;

public class Main {
    static String apikey = "<your api key>";

    public static void main(String args[]) {
        Client c = DNSDB2Client(apikey);
    }
}
```

Once you have instantiated your `Client` object you can call the query functions: `lookupRRSet`, `lookupRData`, and `lookupFlex`. These return `Query` objects. `Client` defines the constants that you need to pass for `type`, `method`, and `key` parameters.

`Query` objects implement a fluent API. Call them in a chain to set options on your query. Query objects are mutable and should not be re-used. `Query.stream()` will raise `QueryLimitedException` unless you call `Query.disableLimitedException(true)`.

Once you have set all parameters on your `Query` you call the `stream()` method to return an `Iterator<JSONObject>` that contains the results of your query. `next()` will raise `QueryLimitedException` if the server indicates that the result limit has been reached (or not, if you have disabled it as mentioned previously).

## Examples

Perform a flex regex search for `farsight`. This manually suppresses `QueryLimitedException` raised by the server if the query results exceed the row limited.

```java
Iterator<JSONObject> it = c.lookupRData(Client.TYPE_NAME, "fsi.io")
        .limit(5)
        .disableLimitedException(true)
        .stream();
while (it.hasNext()) {
    System.out.println(it.next());
}
```

Lookup rrsets for `*.dnsdb.info` with rrtype `A`. 

```java
c.lookupRRSet(Client.TYPE_NAME, "*.dnsdb.info")
        .rrtype("A")
        .stream();
```

Lookup RData for `104.244.13.0/24`
```java
c.lookupRData(Client.TYPE_IP, "104.244.13.0/24")
        .stream();
```
Iterate through a large result set by re-issuing queries with increasing offsets after `QueryLimited` is raised.

```java
int limit = 1000
int offset = 0
while (true) {
    try {
        Iterator<JSONObject> it = c.lookupRRSet("farsightsecurity.com")
                .limit(limit)
                .offset(offset)
                .stream();
        while (it.hasNext()) {
            System.out.println(it.next());
        }
    } catch (QueryLimitedException e) {
        offset += limit;
        continue;
    }
    break;
}
```

## API Documentation

The API is documented with [Javadoc](apidocs/index.html).

https://docs.dnsdb.info/dnsdb-apiv2/

https://docs.dnsdb.info/dnsdb-flex/
