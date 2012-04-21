# com.brweber2/clj-dns

Clojure wrapper library for [dnsjava](http://www.xbill.org/nsjava)

This project can be found on github at [clj-dns](https://github.com/brweber2/clj-dns).

Marginalia documentation can be found at <http://brweber2.github.com/clj-dns/uberdoc.html>.

## Comments

It should be noted that not all functionality from the Java DNS library is exposed directly via the clojure API. Only the common tasks are implemented in a "Clojure friendly" way, the rest are available via Clojure's excellent Java interop.

## Usage

Leiningen

    :dependencies [[com.brweber2/clj-dns "0.0.1"]]

## License

Copyright (C) 2012 brweber2

Distributed under the Eclipse Public License, the same as Clojure.
