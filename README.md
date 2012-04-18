# com.brweber2/clj-dns

Clojure wrapper library for (dnsjava)[http://www.xbill.org/dnsjava]

## Comments

It should be noted that not all functionality from the Java DNS library is exposed directly via the clojure API. Only the common tasks are implemented in a "Clojure friendly" way, the rest are available via Clojure's excellent Java interop.

## Usage

Leiningen

    :dependencies [[com.brweber2/clj-dns "0.0.1-SNAPSHOT"]]

## License

Copyright (C) 2012 brweber2

Distributed under the Eclipse Public License, the same as Clojure.
