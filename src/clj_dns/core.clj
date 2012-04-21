(ns clj-dns.core
  (:import (org.xbill.DNS Name Zone Record Type Master DClass Address Message SimpleResolver SOARecord NSRecord DSRecord CNAMERecord TXTRecord ARecord AAAARecord MXRecord PTRRecord Lookup ReverseMap RRset))
  (:import (org.xbill.DNS.spi DNSJavaNameServiceDescriptor))
  (:import lookup)
  (:import dig)
  (:import java.io.File)
  (:import java.util.List)
  (:import clojure.lang.ISeq))

;; The dnsjava service provider, used for reverse DNS lookup.
;; is this necessary???
(System/setProperty "sun.net.spi.nameservice.provider.1" "dns,dnsjava")

;; ## Default values 
;; (used for creating resource records)

;; TTL is time-to-live
(def dflt-ttl 86400) ; 1 day

;; IN is for Internet. I can almost guarantee this is what you want :)
(def dflt-dclass DClass/IN)

;; Map of default values for resource record creation (making these optional parameters essentially)
(def rr-defaults {:ttl dflt-ttl :dclass dflt-dclass})

;; special defaults for SOA records
(def soa-defaults {
  :refresh   1800  ; 30 minutes
  :retry      900  ; 15 minutes
  :expire  691200  ; 1 week 1 day
  :minimum  10800  ; 3 hours
  })

;; ## Helper functions 
;; (todo protocol better for the 'instance?' cases...?)

;; Convert a string, keyword or symbol to a java.net.InetAddress
(defn to-inet-address [a] (Address/getByName (name a)))

;; Convert a single element, clojure.lang.ISeq or java.util.List to a java.util.List
(defn to-list [x] (condp instance? x String (apply list (flatten [x])) List x ISeq (apply list x)))

;; Convert a File to its aboslute path, otherwise assume the string value is a path
(defn to-filename-string [f] (if (instance? File f) (.getAbsolutePath f) (str f)))

;; Stick a trailing '.' on the end of the string (keyword or symbol) if one is not already present
(defn ensure-trailing-period [a] (let [s (name a)](if-not (.endsWith s ".") (str s ".") s)))

;; Convert the value passed in to a org.xbill.DNS.Name (prefer calling the to-name function below)
(defn dns-name [s] (Name. (ensure-trailing-period s)))

;; Conver the value passed in to a org.xbill.DNS.Name if it is not one already
(defn to-name [n] (if (instance? Name n) n (dns-name n)))

;; Given two org.xbill.DNS.Name instances, check if b is a subdomain of a
(defn sub-domain? [a b] (.subdomain (to-name a) (to-name b)))

;; Predicate that checks if any resource record in the rrs seq has the provided resource record type.
;;
;; The rr-type is an int, but there are constants for the values on org.xbill.DNS.Type (e.g. Type/NS)
(defn has-rr-of-type? [rr-type & rrs] (some #(= rr-type (.getType %)) rrs))

;; converts a map of options for dig to a seq of strings
;; <pre><code>
;; e.g. {:tcp true} will return ["-t"]
;; and {:ignore-trunction true :print-query true} will return ["-i","-p"]
;; </code></pre>
(defn- convert-dig-options [options-map]
  (filter seq [(when (:tcp options-map) "-t") (when (:ignore-trunction options-map) "-i") (when (:print-query options-map) "-p")]))

;; given a map and a sequence of keys, it verifies that either all the keys from the sequence are present in the map or none of them are.
(defn- all-or-none [m s]
  (or (every? #(contains? m %) s)
      (not-any? #(contains? m %) s)))

;; Returns (int 4) for IPv4, (int 6) for IPv6 and error otherwise.
(defn- get-family [^String ip-address]
  (Address/familyOf (Address/getByAddress ip-address)))

;; Takes a string ip address and converts it to a byte[]
(defn ip-address-to-byte-array [^String ip-address]
  (Address/toByteArray ip-address (get-family ip-address)))

;; Takes and IP address and returns the reverse zone.
;; 
;; IPv4 Example:
;; <pre><code>
;; 118.193.14.61 -> 61.14.193.118.in-addr.arpa.
;; </code></pre>
;; So basically, reverse the octects and append '.in-addr.arpa.' Please note the trailing period.
;;
;; IPv6 Example
;; <pre><code>
;; 3721:abcd:: -> 0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.c.b.a.1.2.7.3.ip6.arpa.
;; </code></pre>
;; Again note the trailing period and remember that the reverse zone is 'ip6' and not 'ipv6'.
;; 
;; Finally, this function has no support for CIDR blocks. It only works with full ip addresses.
;;
;; This should actually work for numerous types: String, InetAddress, int[] and byte[]
(defn ip-to-reverse-str [ip-addr]
  (ReverseMap/fromAddress ip-addr))

;; ## Resource Records

;; Functions for creating new instances of common resource record types.
;;
;; If you aren't familiar with a particular resource record type, then I suggest you read some RFCs or wikipedia :)
;; It should be noted that there are many more resource record types, I've just chosen what I believe to be the most common.
;; More might be added later.
;;
;; For each resource record type, there are two ways to call the function. Pretending that xx was a resource record type for a moment, we would have:
;; <pre><code>
;; (rr-xx {:zone "foo.com" :additional-info "more"})
;; </code></pre>
;; vs.
;; <pre><code>
;; (rr-xx "foo.com" "more")
;; </code></pre>
;; It should be noted that the first form allows you to override any default values by placing them in the map, whereas the second form does not.

;; Function for creating a NS resource record.
(defn rr-ns
  ([{:keys [zone dclass ttl the-ns] :or {ttl (:ttl rr-defaults) dclass (:dclass rr-defaults)}}]
    (NSRecord. (to-name zone) (int dclass) (long ttl) (to-name the-ns)))
  ([zone the-ns]
    (rr-ns {:zone zone :the-ns the-ns})))

;; Function for creating a DS resource record.
;;
;; key-tag is called footprint in the Java DNS library
(defn rr-ds
  ([{:keys [zone dclass ttl key-tag algorithm digest-type digest] :or {ttl (:ttl rr-defaults) dclass (:dclass rr-defaults)}}]
    (DSRecord. (to-name zone) (int dclass) (long ttl) key-tag algorithm digest-type digest))
  ([zone key-tag algorithm digest-type digest]
    (rr-ds {:zone zone :key-tag key-tag :algorithm algorithm :digest-type digest-type :digest digest})))

;; Function for creating a SOA resource record.
;;
;; The serial is commonly in the following format 
;; <pre><code>
;; &lt;date in yyyymmdd&gt;&lt;run-of-the-day&gt; &lt;20120420&gt;&lt;01&gt; or 2012042001
;; </code></pre>
;; What generally really matters is that each serial number is numerically larger than the previous ones issued.
(defn rr-soa
  ([{:keys [zone dclass ttl host admin serial refresh retry expire minimum] :or {ttl (:ttl rr-defaults) dclass (:dclass rr-defaults) refresh (:refresh soa-defaults) retry (:retry soa-defaults) expire (:expire soa-defaults) minimum (:minimum soa-defaults)}}]
    (SOARecord. (to-name zone) (int dclass) (long ttl) (to-name host) (to-name admin) (long serial) (long refresh) (long retry) (long expire) (long minimum)))
  ([zone host admin serial]
      (rr-soa {:zone zone :host host :admin admin :serial serial})))

;; Function for creating a TXT resource record.
(defn rr-txt
  ([{:keys [zone dclass ttl lines] :or {ttl (:ttl rr-defaults) dclass (:dclass rr-defaults)}}]
    (TXTRecord. (to-name zone) (int dclass) (long ttl) (to-list lines)))
  ([zone lines]
    (rr-txt {:zone zone :lines lines})))

;; Function for creating a MX resource record.
(defn rr-mx
  ([{:keys [zone dclass ttl priority target] :or {ttl (:ttl rr-defaults) dclass (:dclass rr-defaults)}}] ; todo add default priority?
    (MXRecord. (to-name zone) (int dclass) (long ttl) (int priority) (to-name target)))
  ([zone priority target]
      (rr-mx {:zone zone :priority priority :target target})))

;; Function for creating a CNAME resource record.
(defn rr-cname
  ([{:keys [zone dclass ttl alias] :or {ttl (:ttl rr-defaults) dclass (:dclass rr-defaults)}}]
    (CNAMERecord. (to-name zone) (int dclass) (long ttl) (to-name alias)))
  ([zone alias]
      (rr-cname {:zone zone :alias alias})))

;; Function for creating a PTR resource record.
(defn rr-ptr
  ([{:keys [zone dclass ttl target] :or {ttl (:ttl rr-defaults) dclass (:dclass rr-defaults)}}]
    (PTRRecord. (to-name zone) (int dclass) (long ttl) (to-name target)))
  ([zone target]
      (rr-ptr {:zone zone :target target})))

;; Function for creating an A resource record.
(defn rr-a
  ([{:keys [zone dclass ttl address] :or {ttl (:ttl rr-defaults) dclass (:dclass rr-defaults)}}]
    (ARecord. (to-name zone) (int dclass) (long ttl) (to-inet-address address)))
  ([zone address]
      (rr-a {:zone zone :address address})))

;; Function for creating an AAAA resource record.
(defn rr-aaaa
  ([{:keys [zone dclass ttl address] :or {ttl (:ttl rr-defaults) dclass (:dclass rr-defaults)}}]
    (ARecord. (to-name zone) (int dclass) (long ttl) (to-inet-address address)))
  ([zone address]
      (rr-aaaa {:zone zone :address address})))

;; ### Dummy functions 
;; (part of the hack to create an empty zone)

;; You almost certainly should not call this function.
(defn- dummy-soa [zone-name]
  (rr-soa {:zone zone-name :dclass dflt-dclass :ttl dflt-ttl :host zone-name :admin zone-name :serial 0 :refresh 0 :retry 0 :expire 0 :minimum 0}))

;; You almost certainly should not call this function.
(defn- dummy-ns [zone-name]
  (rr-ns {:zone zone-name :dclass dflt-dclass :ttl dflt-ttl :the-ns zone-name}))

;; ## Common DNS tasks 

;; Lookup hostname(s). This prints the result to stdout, it does not return a seq of the data.
;;
;; This can be used like so:
;; <pre><code>
;; (dns-lookup "www.google.com")
;; </code></pre>
;; or with multiple values:
;; <pre><code>
;; (dns-lookup "www.google.com" "www.bing.com")
;; </code></pre>
;; or if you have a seq of things to look up:
;; <pre><code>
;; (apply dns-lookup ["www.google.com" "www.bing.com"])
;; </code></pre>
(defn dns-lookup-to-stdout [& to-lookups] (lookup/main (into-array String to-lookups)))

;; Lookup hostname(s) by resource record type. This prints the result to stdout, it does not return a seq of the data.
;;
;; example:
;; <pre><code>
;; (dns-loookup-by-type Type/PTR "www.google.com" "www.bing.com")
;; </code></pre>
(defn dns-lookup-by-type-to-stdout [rr-type & to-lookups] (lookup/main (into-array String (into ["-t" (Type/string rr-type)] to-lookups))))

;; Returns a map with two keys (aliases and answers). Each maps to a sequence.
(defn dns-lookup
  ([{:keys [to-lookup rr-type] :or {rr-type Type/A}}]
    (let [lkup (Lookup. (to-name to-lookup) (int rr-type))]
      (.run lkup)
      { :aliases (seq (.getAliases lkup))
        :answers (if (= (.getResult lkup) Lookup/SUCCESSFUL)
                   (seq (.getAnswers lkup))
                   [])}))
  ([to-lookup rr-type] (dns-lookup {:to-lookup to-lookup :rr-type rr-type})))

;; Returns the hostname when passed an ip-address (a reverse DNS lookup).
(defn reverse-dns-lookup [^String ip-address]
  (.getHostByAddr (.createNameService (DNSJavaNameServiceDescriptor.)) (ip-address-to-byte-array ip-address)))

;; Executes a DNS query by passing in a resource record to use as the query. You can optionally provide a resolver.
(defn dns-query
  ([rr]
    (.send (SimpleResolver.) (Message/newQuery rr)))
  ([rslvr rr]
    (.send rslvr (Message/newQuery rr))))

;; dig is a DNS utility that provides a great deal more detail than a simple lookup. It contains all the DNS information in the UDP packets.
;; dig's options look something like:
;;
;; <pre><code>
;; dig [@server] name [&lt;type&gt;] [&lt;class&gt;] [&lt;options&gt;]
;; </code></pre>
;;
;; The type defaults to A and dclass defaults to IN
;; A simple example:
;;
;; (dns-dig {:name "www.google.com"})
;;
;; Again, this prints the result to standard out.
;; use -x &lt;name&gt; for "name" to get a reverse lookup
;; here are the supported options...
;; <pre><code>
;; -p &lt;port&gt;
;; -b &lt;address&gt;
;; -t -- use TCP instead of UDP (DNS uses UDP)
;; -i -- ignore truncation
;; -q -- print the query
;; </code></pre>
;;
;; example
;;
;; (dns-dig-to-stdout {:tcp true :ignore-trunction true :print-query true})
;;
;; and options I decided not to support
;; <pre><code>
;; -k &lt;TSIG&gt; -- not supported here
;; -e &lt;edns&gt; -- not supported here
;; -d &lt;edns&gt; -- not supported here
;; </code></pre>
(defn dns-dig-to-stdout
  [{the-server :server the-name :name the-type :type options-map :options the-class :dclass :as the-args :or {:dclass DClass/IN}}]
  {:pre [(all-or-none the-args [:server :type :dclass])]} ; if :server is present, :class and :type must be as well (for all permutations...)
    (dig/main (into-array String (filter seq (into [the-server the-name the-type the-class] (convert-dig-options options-map))))))

;; ## Ways to get a Zone

;; Generally prefer a Zone over a Master.

;; Read the zone from a file. It can be a java.io.File object or a String file path.
;;
;; Example:
;; <pre><code>
;; (read-zone-from-file "6.0.2.ip6.arpa." "/zones/6.0.2.ip6.arpa")
;; </code></pre>
(defn read-zone-from-file [zone-name zone-file]
  (Zone. (to-name zone-name) (to-filename-string zone-file)))

;; A zone must be seeded with a SOA and at least one NS record. Additional resource records can be passed along with the NS record.
;; 
;; Example
;; <pre><code>
;; (new-zone "6.0.2.ip6.arpa" 
;;           (rr-soa {:zone "6.0.2.ip6.arpa" :host "foo.com." :admin "dns.foo.com." :serial 1400 :refresh 1500 :retry 1600 :expire 1700 :minimum 1800}) 
;;           (rr-ns  {:zone "a.6.0.2.ip6.arpa" :the-ns "ns1.foo.com"}) 
;;           (rr-txt {:zone "b.6.0.2.ip6.arpa" :lines "clojure is fun"}))
;; </code></pre>
(defn new-zone [zone-name ^SOARecord the-soa & rrs]
  {:pre  [(has-rr-of-type? Type/NS rrs)]}
  (Zone. (to-name zone-name) (into-array Record (conj the-soa rrs))))

;; DNS Java requires a SOA and at least one NS record. We'll put placeholders in there and then 
;; remove them, thus creating an empty zone. This allows zonelets (or fragments) to be created
;; and later stitched together to form a complete zone.
(defn zone-fragment
  [zone-name]
  (let [placeholder-soa (dummy-soa zone-name) placeholder-ns (dummy-ns zone-name)]
    (doto (Zone. (to-name zone-name) (into-array Record [placeholder-soa placeholder-ns]))
      (.removeRecord placeholder-soa)
      (.removeRecord placeholder-ns))))

;; Creates a completely empty zone. The idea is that you can build up pieces of a zone from these empty zones and merge them with merge-zones.
(defn empty-zone [] (zone-fragment "."))

;; zone passed in can be a File or InputStream
(defn parse-master [zone]
  (Master. zone))

;; ## Things you can do with an RRSet

;; Generally, prefer to get a seq of resource records, but Java DNS has these RRSet objects, so we expose them as an intermediate abstraction.
(defn rrs-from-rrset [^RRset rrset]
  (iterator-seq (.rrs rrset)))

;; ## Things you can do with a Zone

;; Print the zone as a string
(defn zone-to-str [zone]
  (.toMasterFile zone))

;; Adds all the resource records passed in to the zone
(defn add-rrs [zone & rrs]
  (do
    (doseq [rr rrs] (.addRecord zone rr))
    zone))

;; Get a seq of the rrsets from a zone. Prefer rrs-from-zone which gets a seq of the resource records in this seq of RRSet's
(defn rrsets-from-zone [zone]
  (try
    (iterator-seq (.iterator zone))
    (catch ArrayIndexOutOfBoundsException e [])))

;; Get the resource records from a zone.
(defn rrs-from-zone [zone]
  (flatten (map rrs-from-rrset (rrsets-from-zone zone))))

;; merge resource records from b into a
(defn rrs-into [zone-a zone-b]
  (apply add-rrs zone-a (rrs-from-zone zone-b)))

;; Merge zonelets (or fragments) into a single zone
(defn merge-zones [& zones]
  (let [the-new-zone (empty-zone)]
    (doseq [z zones] (rrs-into the-new-zone z))
    the-new-zone))

;; Removes all the resource records passed in from the zone
(defn remove-rrs [zone & rrs]
  (doseq [rr rrs] (.removeRecord zone rr)))

;; This returns a seq of RRSet's from a zone.
(defn find-rrsets [zone zone-name zone-type]
  (seq (.answers (.findRecords zone (to-name zone-name) (int zone-type)))))

;; This returns a seq of all the resource records from a zone.
(defn find-records [zone zone-name zone-type]
  (doall (map #(rrs-from-rrset %) (find-rrsets zone zone-name zone-type))))

;; ## Master files

;; todo should I to introduce a protocol here to get the rrs from a master/zone?
;;
;; Get the resource records from a master file. Note that this closes the master input stream, which makes this a one shot object.
;; Unless if you really need this, I recommend using a Zone.
(defn rrs-from-master [master]
  (let [v (.nextRecord master)]
    (when-not (nil? v)
      (lazy-seq (cons v (rrs-from-master master))))))
