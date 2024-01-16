(ns aws-simple-sign.core
  "Relevant AWS documentation:
   https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
   https://docs.aws.amazon.com/AmazonS3/latest/userguide/RESTAuthentication.html"
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure-ini.core :as ini])
  (:import [java.net URL]
           [java.time ZoneId ZoneOffset]
           [java.time.format DateTimeFormatter]
           [java.security MessageDigest]
           (java.util Date)
           (javax.crypto Mac)
           (javax.crypto.spec SecretKeySpec)))

(defn hash-sha256
  [^String input]
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

(defn hmac-sha-256
  [key ^String data]
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

(def ^DateTimeFormatter formatter
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
  [canonical-url credentials {:keys [scope method timestamp region service query-params content-sha256 signed-headers]}]
  (let [encoded-url (uri-encode url-unreserved-chars canonical-url)
        signed-headers (->> signed-headers
                            (map (fn [[k v]] [(str/lower-case k) v]))
                            (into (sorted-map)))
        headers-str (->> signed-headers
                         (map (fn [[k v]] (str k ":" (str/trim (or v "")) "\n")))
                         (apply str))
        signed-headers-str (str/join ";" (map key signed-headers))
        query-str (->query-str query-params)
        canonical-request (str (or method "GET") "\n"
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

(defn guarantee-credientials
  [{:aws/keys [access-key secret-key token] :as credentials}]
  (if (and access-key secret-key token)
    credentials
    (throw (ex-info "AWS credentials missing or incomplete - check environment variables." {}))))

(defn as-existing-file
  "Takes a string with the path to the file
   and returns a File object if the file exists otherwise nil."
  [file-path]
  (let [f (io/file file-path)]
    (when (.exists f)
      f)))

(defn read-credentials-file
  [file-path profile-name]
  (when-let [f (as-existing-file file-path)]
    (-> (ini/read-ini f)
        (get profile-name)
        (or {}))))

(defn read-env-credentials
  ([]
   (read-env-credentials (or (System/getenv "AWS_PROFILE") "default")))
  ([profile-name]
   ;; Only try to read AWS files if needed (and only once) by using "delay"
   (let [file-cred (delay (read-credentials-file
                           (or (System/getenv "AWS_SHARED_CREDENTIALS_FILE")
                               (str (System/getProperty "user.home") "/.aws/credentials"))
                           profile-name))
         file-conf (delay (read-credentials-file
                           (or (System/getenv "AWS_CONFIG_FILE")
                               (str (System/getProperty "user.home") "/.aws/config"))
                           (str "profile " profile-name)))]
     (-> {:aws/access-key (or (System/getenv "AWS_ACCESS_KEY_ID")
                              (get @file-cred "aws_access_key_id"))
          :aws/secret-key (or (System/getenv "AWS_SECRET_ACCESS_KEY")
                              (get @file-cred "aws_secret_access_key"))
          :aws/token (or (System/getenv "AWS_SESSION_TOKEN")
                         (get @file-cred "aws_session_token"))
          :aws/region (or (System/getenv "AWS_REGION")
                          (System/getenv "AWS_DEFAULT_REGION")
                          (get @file-conf "region")
                          "us-east-1")}
         (guarantee-credientials)))))

(defn hashed-payload
  [payload]
  (when (or (nil? payload) (string? payload))
    (hex-encode-str (hash-sha256 (or payload "")))))

(defn get-query-params
  [params-str]
  (when (seq params-str)
    (->> (str/split params-str #"&")
         (map (fn [param]
                (let [[k v] (str/split param #"=" 2)]
                  ;; ensure vector with exactly 2 elements (key/value) for `into` to work
                  [k v])))
         (into (sorted-map)))))

(defn sign-request
  ([request opts]
   (sign-request request (read-env-credentials) opts))
  ([{:keys [body headers method url] :as request}
    credentials
    {:keys [ref-time region service]
     :or {region (:aws/region credentials)
          service "execute-api"
          ref-time (Date.)}}]
   (let [timestamp (.format formatter (.toInstant ^Date ref-time))
         service service
         url-obj (URL. url)
         content-sha256 (hashed-payload body)
         signed-headers (-> headers
                            (assoc "Host" (.getHost url-obj)
                                   "x-amz-content-sha256" content-sha256
                                   "x-amz-date" timestamp
                                   "x-amz-security-token" (:aws/token credentials)))
         scope (str (subs timestamp 0 8) "/" region "/" service "/aws4_request")
         signature-str (signature (.getPath url-obj) credentials
                                  {:scope scope
                                   :timestamp timestamp
                                   :region region
                                   :service service
                                   :method (-> method name str/upper-case)
                                   :signed-headers signed-headers
                                   :query-params (get-query-params (.getQuery url-obj))
                                   :content-sha256 content-sha256})]
     (-> request
         (assoc :headers (dissoc signed-headers "Host")) ; overwrite headers to include necessary x-amz-* ones
         (update :headers assoc
                 "Authorization" (str algorithm " Credential=" (:aws/access-key credentials) "/" scope ", "
                                      "SignedHeaders=" (str/join ";" (map key signed-headers)) ", "
                                      "Signature=" signature-str))))))

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
                     :or {expires "3600"
                          region (:aws/region credentials)
                          ref-time (Date.)}}]
   (let [url-obj (URL. url)
         host (.getHost url-obj)
         service "s3"
         timestamp (.format formatter (.toInstant ^Date ref-time))
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
