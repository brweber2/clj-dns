(ns clj-dns.core
  (:import (org.xbill.DNS Name Zone Record Type Master SOARecord DClass Address))
  (:import lookup)
  (:import dig)
  (:import java.io.File)
  (:import java.util.List)
  (:import clojure.lang.ISeq))

(defn todo [] (throw (RuntimeException. "Not yet implemented!")))
(declare to-name)
(declare to-filename-string)
(declare to-inet-address)
(declare rr-has?)
(declare to-list)
(declare dummy-soa)
(declare dummy-ns)
(declare add-rrs)
(declare rrs-from-zone)

;; ### Default values
(def soa-defaults {})
(def default-ttl 86400)
(def default-dclass DClass/IN)
(def rr-defaults {:ttl default-ttl :dclass default-dclass})

;; ## Common DNS tasks

(defn dns-lookup [& to-lookups] (lookup/main (into-array String to-lookups)))
(defn dns-lookup-by-type [rr-type & to-lookups] (lookup/main (into-array String (into ["-t" rr-type] to-lookups))))
; - reverse lookup?

(defn convert-dig-options
  [options-map]
  (filter seq [(when (:tcp options-map) "-t") (when (:ignore-trunction options-map) "-i") (when (:print-query options-map) "-p")]))

(defn all-or-none
  [m s] ; map m must contain each keyword from s or none of them
  (or (every? #(contains? m %) s)
      (not-any? #(contains? m %) s)))

;; dig [@server] name [<type>] [<class>] [<options>]
;; type defaults to A and class defaults to IN
;; we might not want type A, but we're always going to default to class IN
;; use -x <name> for "name" to get a reverse lookup
;; here are the supported options...
;; -p <port>
;; -b <address>
;; -t -- use TCP instead of UDP
;; -i -- ignore truncation
;; -q -- print the query
;; (example-dig-options {:tcp true :ignore-trunction true :print-query true})
;; and options I decided not to support
;; -k <TSIG> -- not supported here
;; -e <edns> -- not supported here
;; -d <edns> -- not supported here
(defn dns-dig
  [{the-server :server the-name :name the-type :type options-map :options the-class :dclass :as the-args :or {:dclass DClass/IN}}]
  {:pre [(all-or-none the-args [:server :type :dclass])]} ; if :server is present, :class and :type must be as well (for all permutations...)
    (dig/main (into-array String (filter seq (into [the-server the-name the-type the-class] (convert-dig-options options-map))))))

;; ## Ways to get a zone (generally prefer a Zone over a Master)

;; Read the zone from a file. It can be a java.io.File object or a String file path.
(defn new-zone [zone-name zone-file]
  (Zone. (to-name zone-name) (to-filename-string zone-file)))

;; A zone must be seeded with a SOA and at least one NS record
(defn new-zone [zone-name ^SOARecord the-soa & rrs]
  {:pre  [(rr-has? Type/NS rrs)]}
  (Zone. (to-name zone-name) (into-array Record (conj the-soa rrs))))

;; DNS Java requires a SOA and at least one NS record. We'll put placeholders in there and then 
;; remove them, thus creating an empty zone. This allows zonelets (or fragments) to be created
;; and later stitched together to form a complete zone.
(defn empty-zone
  [zone-name]
  (let [placeholder-soa (dummy-soa) placeholder-ns (dummy-ns)]
  (doto (Zone. (to-name zone-name) (into-array Record [placeholder-soa placeholder-ns]))
    (.removeRecord placeholder-soa)
    (.removeRecord placeholder-ns))))

;; zone passed in can be a File or InputStream
(defn parse-master [zone]
  (Master. zone))

;; ## Things you can do with a zone

;; Print the zone as a string
(defn zone-to-str [zone]
  (.toMasterFile zone))

;; merge resource records from b into a
(defn rrs-into [a b]
  (add-rrs a (rrs-from-zone b)))

;; Merge zonelets (or fragments) into a single zone
(defn merge-zones [& zones]
  (let [new-zone (empty-zone)]
    (doseq (map (partial rrs-into new-zone) zones))))

;; todo need to introduce a protocol here to get the rrs from a master/zone
;; Get the resource records from a master file. Note that this closes the master input stream.
(defn rrs-from-master [master]
  (let [v (.nextRecord master)]
    (when-not (nil? v)
      (lazy-seq (cons v (rrs-from-master master))))))

; Get the resource records from a zone.
(defn rrs-from-zone [zone]
  (iterator-seq (.iterator zone)))

;; Adds all the resource records passed in to the zone
(defn add-rrs [zone & rrs]
  (doseq (map #(.addRecord zone %) rrs)))

;; Removes all the resource records passed in from the zone
(defn remove-rrs [zone & rrs]
  (doseq (map #(.removeRecord zone %) rrs)))

(defn find-records [zone zone-name zone-type]
  (.findRecords zone (to-name zone-name) (int zone-type)))

;; ## Resource Records
(defn rr-ns [{zone-name :zone ttl :ttl the-ns :ns dclass :dclass :or rr-defaults}]
  (NSRecord. (to-name zone-name) dclass (long ttl) (to-name the-ns)))
(defn rr-ds [{:keys [zone dlcass ttl key-tag algorithm digest-type digest] :or rr-defaults}]
  (DSRecord. (to-name zone) dclass (long ttl) key-tag algorithm digest-type digest)) ; key-tag is called footprint in the Java DNS library
(defn rr-soa [{:keys [zone dclass ttl host admin serial refresh retry expire minimum] :or rr-defaults}]
  (SOARecord. (to-name zone) dclass (long ttl) (to-name host) (to-name admin) (long serial) (long refresh) (long retry) (long expire) (long minimum)))
(defn rr-txt [{:keys [zone dclass ttl lines] :or rr-defaults}]
  (TXTRecord. (to-name zone) dlcass (long ttl) (to-list lines)))
(defn rr-mx [{:keys [zone dclass ttl priority target] :or rr-defaults}] ; todo add default priority?
  (MXRecord. (to-name zone) dclass (long ttl) (int priority) (to-name target)))
(defn rr-cname [{:keys [zone dclass ttl alias] :or rr-defaults}]
  (CNAMERecord. (to-name zone) dclass (long ttl) (to-name alias)))
(defn rr-ptr [{:keys [zone dclass ttl target] :or rr-defaults}]
  (PTRRecord. (to-name zone) dclass (long ttl) (to-name target)))
(defn rr-a [{:keys [zone dclass ttl address] :or rr-defaults}]
  (ARecord. (to-name zone) dclass (long ttl) (to-inet-address address)))
(defn rr-aaaa [{:keys [zone dclass ttl address] :or rr-defaults}]
  (ARecord. (to-name zone) dclass (long ttl) (to-inet-address address)))

(defn dummy-soa [] (rr-soa {:zone "." :host "." :admin "." 0 0 0 0 0}))
(defn dummy-ns [] (rr-ns {:zone "." :ns "."}))

;; ## Helper functions (todo protocol better for the instance? cases...?)
(defn to-inet-address [a] (Address/getByName (name a)))
(defn to-list [x] ; could have a single element, seq or java.util.List
  (condp instance? x String (apply list (flatten [x])) List x ISeq (apply list x)))
(defn to-filename-string [f] (if (instance? File f) (.getAbsolutePath f) (str f)))
(defn ensure-trailing-period [a] (let [s (name a)](if-not (.endsWith s ".") (str s ".") s)))
(defn dns-name [s] (Name. (ensure-trailing-period s)))
(defn to-name [n] (if (instance? Name n) n (dns-name n)))
(defn sub-domain? [a b] (.subdomain (to-name a) (to-name b)))
(defn rr-has? [rr-type & rrs] (some #(= rr-type (.getType %)) rrs))


