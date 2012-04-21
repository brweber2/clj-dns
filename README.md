# com.brweber2/clj-dns

Clojure wrapper library for [dnsjava](http://www.xbill.org/dnsjava)

This project can be found on github at [clj-dns](https://github.com/brweber2/clj-dns).

Annotated source code documentation (Marginalia) can be found at <http://brweber2.github.com/clj-dns/uberdoc.html>.

## Comments

It should be noted that not all functionality from the dnsjava library is exposed directly via the Clojure API. Only the common tasks are implemented in a "Clojure friendly" way, the rest are available via Clojure's excellent Java interop. In particular, zone transfers are not exposed directly.

The documentation here is by no means complete. See the Marginalia clj-dns documentation for more details. Anywhere that you see ```(rr-ns …)``` that of course means you have to fill out the actual details as documented in the Resource Records section below.

## Install

Development is currently at version 0.0.3-SNAPSHOT, however I recommend using 0.0.2 for the time being until 0.0.3 stabilizes.

Leiningen

    :dependencies [[com.brweber2/clj-dns "0.0.2"]]

Maven

    <dependency>
        <groupId>com.brweber2</groupId>
        <artifactId>clj-dns</artifactId>
        <version>0.0.2</version>
    </dependency>

## Usage

### The namespace

    (use clj-dns.core)
    
or something like this

    (ns your-ns
      (:use [clj-dns.core :only [rr-ns]]))

### Querying

#### Lookup

    (import 'org.xbill.DNS.Type)
    (dns-lookup "www.google.com" Type/A)
    
or
    
    (dns-query (rr-ns …))
    (dns-query a-resolver (rr-ns ...))

Resolvers are not covered here. If you need something that is not the default, then I suggest you read the documentation of dnsjava.

#### Reverse Lookup

    (reverse-dns-lookup "192.168.0.0")

### Resource Records

#### Format

* Name - Identifies the node in the DNS tree.
* Type - The type of the resource record.
* Class - You almost certainly want this to be IN for Internet.
* RData - Additional data that is dependend upon the Type.

#### Examples

* Name

Proper names end in a period. The to-name function adds it for you if it is missing.

    (to-name "www.google.com")

or

    (to-name "14.15.16.17.in-addr.arpa")

If you have an ip address, you can convert it to a reverse zone. This means that ```17.16.15.14``` converts to ```14.15.16.17.in-addr.arpa.```.

    (ip-to-reverse-string "17.16.15.14")

* Type

There are constants defined already for the types.

    (import 'org.xbill.DNS.Type)
    Type/CNAME

* Class

To use IN as the class

    (import 'org.xbill.DNS.DClass)
    DClass/IN

* RData

The RData depends on the specific record type, but let's us a NS record as an example. We have the rr-ns function which takes the name and extra data as a second parameter.

    (use 'clj-dns.core)
    (rr-ns "www.google.com" "ns1.google.com")

If you need to provide more details, you can use the following form:

    (use 'clj-dns.core)
    (import 'org.xbill.DNS.DClass)
    (rr-ns {:name "www.google.com" :dclass DClass/IN :ttl 24000 :the-ns "ns1.google.com"})

You can also get the name of a resource record as a String

    (rr-name some-rr)
    
Or get the resource record type as a readable String (as opposed to an int)

    (rr-type some-rr)

### Zone files

#### Building

* Build programmatically

With resource records
 
    (new-zone "foo.com" (rr-soa …) (rr-ns …) (rr-ns ...))    
    
Empty
    
    (empty-zone)
    
The idea with empty zones is that you can build up multiple zone fragments and stitch them together. The resulting zone should have only one SOA record and at least one NS record.

    (merge-zones zone1 zone2 zone3)


#### Reading

Read from a file

    (read-zone-from-file "foo.com" "/zones/foo.com")

#### Writing

Write to a String

    (zone-to-str a-zone)
    
##### Manipulating

Add resource records to a zone

    (add-rrs a-zone (rr-ns …) (rr-ns ...))

Remove resource records from a zone

    (remove-rrs a-zone (rr-ns …) (rr-ns …))

Get all the resource records in a zone

    (rrs-from-zone a-zone)

Find particular resource records in a zone

    (find-rrs a-zone zone-name zone-type))
    
#### Zone transfers

Not covered here.

## License

Copyright (C) 2012 brweber2

Distributed under the Eclipse Public License, the same as Clojure.
