(ns clj-dns.core
  (:import (org.xbill.DNS Name Zone Record Type Master SOARecord DClass))
  (:import lookup)
  (:import dig)
  (:import java.io.File))

(defn todo [] (throw (RuntimeException. "Not yet implemented!")))
(declare to-name)
(declare to-filename-string)
(declare rr-has?)
(declare dummy-soa)
(declare dummy-ns)
(declare add-rrs)
(declare rrs-from-zone)

;; ### Default values
(def soa-defaults {})

;; ## Common DNS tasks

(defn dns-lookup [& to-lookups] (lookup/main (into-array String to-lookups)))
(defn dns-lookup-by-type [rr-type & to-lookups] (lookup/main (into-array String (into ["-t" rr-type] to-lookups))))
; todo reverse lookup?

(defn convert-dig-options
  [options-map]
  (filter seq [(when (:tcp options-map) "-t") (when (:ignore-trunction options-map) "-i") (when (:print-query options-map) "-p")]))

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
  ([the-name] (dig/main (into-array String [the-name])))
  ([the-name options-map] (dig/main (into-array String (into [the-name] (convert-dig-options options-map)))))
  ([the-server the-name the-type] (dig/main (into-array String [the-server the-name the-type DClass/IN])))
  ([the-server the-name the-type options-map] (dig/main (into-array String (into [the-server the-name the-type DClass/IN] (convert-dig-options options-map))))))

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
    (doall (map (partial rrs-into new-zone) zones))))

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
  (doall (map #(.addRecord zone %) rrs)))

;; Removes all the resource records passed in from the zone
(defn remove-rrs [zone & rrs]
  (doall (map #(.removeRecord zone %) rrs)))

(defn find-records [zone zone-name zone-type]
  (.findRecords zone (to-name zone-name) (int zone-type)))

;; ## Resource Records
(defn rr-ns [] (todo))
(defn rr-ds [] (todo))
(defn rr-soa [] (todo))
(defn rr-txt [] (todo))
(defn rr-mx [] (todo))
(defn rr-cname [] (todo))
(defn rr-ptr [] (todo))
(defn rr-a [] (todo))
(defn rr-aaaa [] (todo))

(defn dummy-soa [] (todo))
(defn dummy-ns [] (todo))

;; ## Helper functions (todo protocol better for the isa? cases...?)
(defn to-filename-string [f] (if (isa? File f) (.getAbsolutePath f) (str f)))
(defn ensure-trailing-period [a] (let [s (name a)](if-not (.endsWith s ".") (str s ".") s)))
(defn dns-name [s] (Name. (ensure-trailing-period s)))
(defn to-name [n] (if (isa? Name n) n (dns-name n)))
(defn sub-domain? [a b] (.subdomain (to-name a) (to-name b)))
(defn rr-has? [rr-type & rrs] (some #(= rr-type (.getType %)) rrs))


