(ns aws-simple-sign.core
  "Relevant AWS documentation:
   https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
   https://docs.aws.amazon.com/AmazonS3/latest/userguide/RESTAuthentication.html"
  (:require [clojure.string :as str]
            [clojure-ini.core :as ini]
            [pod.babashka.buddy.core.codecs :as codecs]
            [pod.babashka.buddy.core.hash :as hash])
  (:import [java.time ZoneId ZoneOffset]
           [java.time.format DateTimeFormatter]
           (javax.crypto Mac)
           (javax.crypto.spec SecretKeySpec)))

;; Clojure implementation of signature
;; https://gist.github.com/souenzzo/21f3e81b899ba3f04d5f8858b4ecc2e9
;; https://github.com/joseferben/clj-aws-sign/ (ring middelware)

(defn hmac-sha-256 [key data]
  (let [algo "HmacSHA256"
        mac (Mac/getInstance algo)]
    (.init mac (SecretKeySpec. key algo))
    (.doFinal mac (.getBytes data "UTF-8"))))

(defn char-range
  [start end]
  (map char (range (int start) (inc (int end)))))

(def unreserved-chars
  (->> (concat '(\- \. \_ \~)
               (char-range \A \Z)
               (char-range \a \z)
               (char-range \0 \9))
       (into #{})))

(def url-unreserved-chars
  (conj unreserved-chars \/))

(defn encode
  [skip-chars c]
  (if (skip-chars c)
    c
    (let [byte-val (int c)]
      (format "%%%X" byte-val))))

(defn uri-encode
  [skip-chars uri]
  (->> uri
       (map (partial encode skip-chars))
       (apply str)))

(def formatter
  (-> (DateTimeFormatter/ofPattern "yyyyMMdd'T'HHmmss'Z'")
      (.withZone (ZoneId/from ZoneOffset/UTC))))

(defn compute-signature
  [{:keys [credentials encoded-policy region short-date]}]
  (let [date-key (-> (str "AWS4" (:aws/secret-key credentials))
                     (.getBytes)
                     (hmac-sha-256 short-date))
        date-region-key (hmac-sha-256 date-key region)
        date-region-service-key (hmac-sha-256 date-region-key "s3")
        signing-key (hmac-sha-256 date-region-service-key "aws4_request")]
    (-> (hmac-sha-256 signing-key encoded-policy)
        (codecs/bytes->hex))))

(def algorithm
  "AWS4-HMAC-SHA256")

(defn sign
  "AWS specification: https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
   Inspired by https://gist.github.com/souenzzo/21f3e81b899ba3f04d5f8858b4ecc2e9"
  [canonical-url credentials {:keys [ref-time region expires content-sha256 signed-headers]}]
  (let [encoded-url (uri-encode url-unreserved-chars canonical-url)
        signed-headers (->> signed-headers
                            (into (sorted-map)))
        headers-str (->> signed-headers
                         (map (fn [[k v]] (str k ":" (str/trim v) "\n")))
                         (apply str))
        signed-headers-str (str/join ";" (map key signed-headers))
        timestamp (.format formatter (.toInstant ref-time))
        date-str (subs timestamp 0 8)
        scope (str date-str "/" region "/s3/aws4_request")
        query-str (->> (conj {"X-Amz-Algorithm" algorithm
                              "X-Amz-Credential" (str (:aws/access-key credentials) "/" scope)
                              "X-Amz-Date" timestamp
                              "X-Amz-SignedHeaders" signed-headers-str}
                             (when-let [token (:aws/token credentials)]
                               ["X-Amz-Security-Token" token])
                             (when expires
                               ["X-Amz-Expires" expires]))
                       (map (fn [[k v]] [(uri-encode unreserved-chars k) (uri-encode unreserved-chars v)]))
                       (into (sorted-map)) ; sort AFTER URL encoding
                       (map (fn [[k v]] (str k "=" v)))
                       (str/join "&"))
        canonical-request (str "GET\n"
                               encoded-url "\n"
                               query-str "\n"
                               headers-str "\n"
                               signed-headers-str "\n"
                               (or content-sha256 "UNSIGNED-PAYLOAD"))
        str-to-sign (str algorithm "\n"
                         timestamp "\n"
                         scope "\n"
                         (codecs/bytes->hex (hash/sha256 canonical-request)))
        signature (compute-signature {:credentials    credentials
                                      :encoded-policy str-to-sign
                                      :region         region
                                      :short-date     date-str})]
    (println "# signature")
    (println signature)
    (str "https://s3." region ".amazonaws.com" encoded-url "?" query-str "&X-Amz-Signature=" signature)))


