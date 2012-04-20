(ns clj-dns.core
  (:import (org.xbill.DNS Name Zone Record Type Master DClass Address SOARecord NSRecord DSRecord CNAMERecord TXTRecord ARecord AAAARecord MXRecord PTRRecord))
  (:import lookup)
  (:import dig)
  (:import java.io.File)
  (:import java.util.List)
  (:import clojure.lang.ISeq))

;; ## Default values (used for creating resource records)

;; special defaults for SOA records
(def soa-defaults {
  :refresh 1800   ; 30 minutes
  :retry 900      ; 15 minutes
  :expire 691200  ; 1 week 1 day
  :minimum 10800  ; 3 hours
  })
;; TTL is time-to-live
(def dflt-ttl 86400) ; 1 day
;; IN is for Internet. I can almost guarantee this is what you want :)
(def dflt-dclass DClass/IN)
;; Map of default values for resource record creation (making these optional parameters essentially)
(def rr-defaults {:ttl dflt-ttl :dclass dflt-dclass})

;; ## Helper functions (todo protocol better for the instance? cases...?)

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
;; Predicate that checks if any resource record in the rrs seq has the provided resource record type
;; The rr-type is an int, but there are constants for the values on org.xbill.DNS.Type (e.g. Type/NS)
(defn rr-has? [rr-type & rrs] (some #(= rr-type (.getType %)) rrs))

;; converts a map of options for dig to a seq of strings
;; e.g. {:tcp true} will return '("-t")
;; and {:ignore-trunction true :print-query true} will return '("-i" "-p")
(defn- convert-dig-options
  [options-map]
  (filter seq [(when (:tcp options-map) "-t") (when (:ignore-trunction options-map) "-i") (when (:print-query options-map) "-p")]))

;; given a map and a sequence of keys, it verifies that either all the keys from the sequence are present in the map or none of them are.
(defn- all-or-none
  [m s] ; map m must contain each keyword from s or none of them
  (or (every? #(contains? m %) s)
      (not-any? #(contains? m %) s)))

;; ## Resource Records
;; Functions for creating new instances of common resource record types.
;; If you aren't familiar with a particular resource record type, then I suggest you read some RFCs or wikipedia :)
;; It should be noted that there are many more resource record types, I've just chosen what I believe to be the most common.
;; More might be added later.
(defn rr-ns [{:keys [zone dclass ttl the-ns] :or {ttl (:ttl rr-defaults) dclass (:dclass rr-defaults)}}]
  (NSRecord. (to-name zone) (int dclass) (long ttl) (to-name the-ns)))
;; key-tag is called footprint in the Java DNS library
(defn rr-ds [{:keys [zone dclass ttl key-tag algorithm digest-type digest] :or {ttl (:ttl rr-defaults) dclass (:dclass rr-defaults)}}]
  (DSRecord. (to-name zone) (int dclass) (long ttl) key-tag algorithm digest-type digest))
;; The serial is commonly in the following format <date in yyyymmdd><run-of-the-day> <20120420><01> or 2012042001
;; What generally really matters is that each serial number is numerically larger than the previous ones issued.
(defn rr-soa [{:keys [zone dclass ttl host admin serial refresh retry expire minimum] :or {ttl (:ttl rr-defaults) dclass (:dclass rr-defaults) refresh (:refresh soa-defaults) retry (:retry soa-defaults) expire (:expire soa-defaults) minimum (:minimum soa-defaults)}}]
  (SOARecord. (to-name zone) (int dclass) (long ttl) (to-name host) (to-name admin) (long serial) (long refresh) (long retry) (long expire) (long minimum)))
(defn rr-txt [{:keys [zone dclass ttl lines] :or {ttl (:ttl rr-defaults) dclass (:dclass rr-defaults)}}]
  (TXTRecord. (to-name zone) (int dclass) (long ttl) (to-list lines)))
(defn rr-mx [{:keys [zone dclass ttl priority target] :or {ttl (:ttl rr-defaults) dclass (:dclass rr-defaults)}}] ; todo add default priority?
  (MXRecord. (to-name zone) (int dclass) (long ttl) (int priority) (to-name target)))
(defn rr-cname [{:keys [zone dclass ttl alias] :or {ttl (:ttl rr-defaults) dclass (:dclass rr-defaults)}}]
  (CNAMERecord. (to-name zone) (int dclass) (long ttl) (to-name alias)))
(defn rr-ptr [{:keys [zone dclass ttl target] :or {ttl (:ttl rr-defaults) dclass (:dclass rr-defaults)}}]
  (PTRRecord. (to-name zone) (int dclass) (long ttl) (to-name target)))
(defn rr-a [{:keys [zone dclass ttl address] :or {ttl (:ttl rr-defaults) dclass (:dclass rr-defaults)}}]
  (ARecord. (to-name zone) (int dclass) (long ttl) (to-inet-address address)))
(defn rr-aaaa [{:keys [zone dclass ttl address] :or {ttl (:ttl rr-defaults) dclass (:dclass rr-defaults)}}]
  (ARecord. (to-name zone) (int dclass) (long ttl) (to-inet-address address)))

;; ### Dummy functions (part of the hack to create an empty zone)
(defn- dummy-soa [zone-name] (rr-soa {:zone zone-name :dclass dflt-dclass :ttl dflt-ttl :host zone-name :admin zone-name :serial 0 :refresh 0 :retry 0 :expire 0 :minimum 0}))
(defn- dummy-ns [zone-name] (rr-ns {:zone zone-name :dclass dflt-dclass :ttl dflt-ttl :the-ns zone-name}))

;; ## Common DNS tasks 
;; These are helpful from a REPL for example, but not generally in a program because they print results to standard out.

;; Lookup hostname(s). This prints the result to stdout, it does not return a seq of the data.
;; This can be used like so:
;; (dns-lookup "www.google.com")
;; or with multiple values:
;; (dns-lookup "www.google.com" "www.bing.com")
(defn dns-lookup [& to-lookups] (lookup/main (into-array String to-lookups)))
;; Lookup hostname(s) by resource record type. This prints the result to stdout, it does not return a seq of the data.
;; example:
;; (dns-loookup-by-type Type/PTR "www.google.com" "www.bing.com")
(defn dns-lookup-by-type [rr-type & to-lookups] (lookup/main (into-array String (into ["-t" (Type/string rr-type)] to-lookups))))
;; todo - add function for reverse lookup

;; dig is a DNS utility that provides a great deal more detail than a simple lookup. It contains all the DNS information in the UDP packets.
;; dig's options look something like:
;; dig [@server] name [<type>] [<class>] [<options>]
;; <pre><code>
;; The type defaults to A and dclass defaults to IN
;; A simple example:
;; (dns-dig {:name "www.google.com"})
;; Again, this prints the result to standard out.
;; use -x <name> for "name" to get a reverse lookup
;; here are the supported options...
;; -p <port>
;; -b <address>
;; -t -- use TCP instead of UDP (DNS uses UDP)
;; -i -- ignore truncation
;; -q -- print the query
;; example
;; (dns-dig {:tcp true :ignore-trunction true :print-query true})
;; and options I decided not to support
;; -k <TSIG> -- not supported here
;; -e <edns> -- not supported here
;; -d <edns> -- not supported here
;; </code></pre>
(defn dns-dig
  [{the-server :server the-name :name the-type :type options-map :options the-class :dclass :as the-args :or {:dclass DClass/IN}}]
  {:pre [(all-or-none the-args [:server :type :dclass])]} ; if :server is present, :class and :type must be as well (for all permutations...)
    (dig/main (into-array String (filter seq (into [the-server the-name the-type the-class] (convert-dig-options options-map))))))

;; ## Ways to get a zone (generally prefer a Zone over a Master)

;; Read the zone from a file. It can be a java.io.File object or a String file path.
;; Example:
;; (read-zone-from-file "6.0.2.ip6.arpa." "/zones/6.0.2.ip6.arpa")
(defn read-zone-from-file [zone-name zone-file]
  (Zone. (to-name zone-name) (to-filename-string zone-file)))

;; A zone must be seeded with a SOA and at least one NS record. Additional resource records can be passed along with the NS record.
;; Example
;; (new-zone "6.0.2.ip6.arpa" 
;;           (rr-soa {:zone "6.0.2.ip6.arpa" :host "foo.com." :admin "dns.foo.com." :serial 1400 :refresh 1500 :retry 1600 :expire 1700 :minimum 1800}) 
;;           (rr-ns  {:zone "a.6.0.2.ip6.arpa" :the-ns "ns1.foo.com"}) 
;;           (rr-txt {:zone "b.6.0.2.ip6.arpa" :lines "clojure is fun"}))
(defn new-zone [zone-name ^SOARecord the-soa & rrs]
  {:pre  [(rr-has? Type/NS rrs)]}
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

(defn empty-zone [] (zone-fragment "."))

;; zone passed in can be a File or InputStream
(defn parse-master [zone]
  (Master. zone))

;; ## Things you can do with a zone

;; Print the zone as a string
(defn zone-to-str [zone]
  (.toMasterFile zone))

;; Adds all the resource records passed in to the zone
(defn add-rrs [zone & rrs]
  (doseq [] (map #(.addRecord zone %) rrs)))

(defn rrsets-from-zone [zone]
  (iterator-seq (.iterator zone)))

(defn rrs-from-rrset [rrset]
  (iterator-seq (.rrs rrset)))

;; Get the resource records from a zone.
(defn rrs-from-zone [zone]
  (doseq [] (map rrs-from-rrset (rrsets-from-zone zone))))

;; merge resource records from b into a
(defn rrs-into [a b]
  (add-rrs a (rrs-from-zone b)))

;; Merge zonelets (or fragments) into a single zone
(defn merge-zones [zone-name & zones]
  (let [new-zone (empty-zone zone-name)]
    (doseq [] (map (partial rrs-into new-zone) zones))))

;; todo need to introduce a protocol here to get the rrs from a master/zone
;; Get the resource records from a master file. Note that this closes the master input stream.
(defn rrs-from-master [master]
  (let [v (.nextRecord master)]
    (when-not (nil? v)
      (lazy-seq (cons v (rrs-from-master master))))))

;; Removes all the resource records passed in from the zone
(defn remove-rrs [zone & rrs]
  (doseq [] (map #(.removeRecord zone %) rrs)))

(defn find-records [zone zone-name zone-type]
  (.findRecords zone (to-name zone-name) (int zone-type)))

