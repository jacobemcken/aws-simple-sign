(ns aws-simple-sign.core
  "Relevant AWS documentation:
   https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
   https://docs.aws.amazon.com/AmazonS3/latest/userguide/RESTAuthentication.html"
  (:require [clojure.set :as set]
            [clojure.string :as str]
            [clojure-ini.core :as ini])
  (:import [java.net URL]
           [java.time ZoneId ZoneOffset]
           [java.time.format DateTimeFormatter]
           [java.security MessageDigest]
           (javax.crypto Mac)
           (javax.crypto.spec SecretKeySpec)))

(defn hash-sha256
  [input]
  (let [hash (MessageDigest/getInstance "SHA-256")]
    (.update hash (.getBytes input))
    (.digest hash)))

(def digits
  (char-array "0123456789abcdef"))

(defn hex-encode
  [bytes]
  (->> bytes
       (mapcat #(list (get digits (bit-shift-right (bit-and 0xF0 %) 4))
                      (get digits (bit-and 0x0F %))))))

(defn hex-encode-str
  [bytes]
  (->> bytes
       (hex-encode)
       (apply str)))

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
  [{:keys [credentials str-to-sign region service short-date]}]
  (-> (str "AWS4" (:aws/secret-key credentials))
      (.getBytes)
      (hmac-sha-256 short-date)
      (hmac-sha-256 region)
      (hmac-sha-256 service)
      (hmac-sha-256 "aws4_request")
      (hmac-sha-256 str-to-sign)
      hex-encode-str))

(def algorithm
  "AWS4-HMAC-SHA256")

(defn ->query-str
  [query-params]
  (->> query-params
       (map (fn [[k v]] [(uri-encode unreserved-chars k) (uri-encode unreserved-chars v)]))
       (into (sorted-map)) ; sort AFTER URL encoding
       (map (fn [[k v]] (str k "=" v)))
       (str/join "&")))

(defn signature
  "AWS specification: https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
   Inspired by https://gist.github.com/souenzzo/21f3e81b899ba3f04d5f8858b4ecc2e9"
  [canonical-url credentials {:keys [scope timestamp region service query-params content-sha256 signed-headers]}]
  (let [encoded-url (uri-encode url-unreserved-chars canonical-url)
        signed-headers (->> signed-headers
                            (into (sorted-map)))
        headers-str (->> signed-headers
                         (map (fn [[k v]] (str k ":" (str/trim v) "\n")))
                         (apply str))
        signed-headers-str (str/join ";" (map key signed-headers))
        query-str (->query-str query-params)
        canonical-request (str "GET\n"
                               encoded-url "\n"
                               query-str "\n"
                               headers-str "\n"
                               signed-headers-str "\n"
                               (or content-sha256 "UNSIGNED-PAYLOAD"))
        str-to-sign (str algorithm "\n"
                         timestamp "\n"
                         scope "\n"
                         (hex-encode-str (hash-sha256 canonical-request)))]
    (compute-signature {:credentials credentials
                        :str-to-sign str-to-sign
                        :region region
                        :service service
                        :short-date (subs timestamp 0 8)})))

(defn read-env-credentials
  ([]
   (read-env-credentials (or (System/getenv "AWS_PROFILE") "default")))
  ([profile-name]
   (-> (str (System/getenv "HOME") "/.aws/credentials")
       (ini/read-ini)
       (get profile-name)
       (set/rename-keys {"aws_access_key_id" :aws/access-key
                         "aws_secret_access_key" :aws/secret-key
                         "aws_session_token" :aws/token}))))

(defn presign
  "Take an URL for a S3 object and returns a string with a presigned GET-URL
   for that particular object.
   Takes the following options (a map) as the last argument,
   the map value shows the default values:
       {:ref-time (java.util.Date.) ; timestamp incorporated into the signature
        :expires \"3600\"           ; signature expires x seconds after ref-time
        :region \"us-east-1\"}      ; signature locked to AWS region
   
   By default credentials are read from standard AWS location."
  ([url]
   (presign url (read-env-credentials) {}))
  ([url opts]
   (presign url (read-env-credentials) opts))
  ([url credentials {:keys [ref-time region expires]
                     :or {expires "3600" region "us-east-1" ref-time (java.util.Date.)}}]
   (let [url-obj (URL. url)
         host (.getHost url-obj)
         service "s3"
         timestamp (.format formatter (.toInstant ref-time))
         scope (str (subs timestamp 0 8) "/" region "/" service "/aws4_request")
         query-params (conj {"X-Amz-Algorithm" algorithm
                             "X-Amz-Credential" (str (:aws/access-key credentials) "/" scope)
                             "X-Amz-Date" timestamp
                             "X-Amz-SignedHeaders" "host"}
                            (when-let [token (:aws/token credentials)]
                              ["X-Amz-Security-Token" token])
                            (when expires
                              ["X-Amz-Expires" expires]))
         signature (signature (.getPath url-obj)
                              credentials
                              {:timestamp timestamp
                               :region region
                               :service service
                               :scope scope
                               :query-params query-params
                               :signed-headers {"host" host}})]
     (str (.getProtocol url-obj) "://" host (.getPath url-obj) "?"
          (->query-str query-params)
          "&X-Amz-Signature=" signature))))
