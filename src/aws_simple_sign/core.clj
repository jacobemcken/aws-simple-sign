(ns aws-simple-sign.core
  "Relevant AWS documentation:

   - https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
   - https://docs.aws.amazon.com/AmazonS3/latest/userguide/RESTAuthentication.html

   When the documentation references a client it is either a [awyeah][1] client,
   a [Cognitect AWS API][2] client or a map with the following structure:

       {:credentials #:aws{:access-key-id \"some-access-key\"
                           :secret-access-key \"wild_secr3t\"
                           :session-token \"FwoG...\"}
        :region \"us-east-1\"
        :endpoint {:protocol :https
                   :hostname \"s3.amazonaws.com\"}}

   Notice: `:endpoint` is optional.

   [1]: https://github.com/grzm/awyeah-api
   [2]: https://github.com/cognitect-labs/aws-api"
  (:require [clojure.string :as str])
  (:import [java.io InputStream]
           [java.net URL]
           [java.time ZoneId ZoneOffset]
           [java.time.format DateTimeFormatter]
           [java.security MessageDigest]
           (java.util Date)
           (javax.crypto Mac)
           (javax.crypto.spec SecretKeySpec)))

 (defmulti hash-sha256
   "Takes input like String or InputStream and returns a SHA256 hash."
   (fn [input]
     (cond
       (instance? java.io.InputStream input)
       :input-stream

       (= String (type input))
       :string)))

(defmethod hash-sha256 :string
  [^String input]
  (let [hash (MessageDigest/getInstance "SHA-256")]
    (.update hash (.getBytes input))
    (.digest hash)))

(defmethod hash-sha256 :input-stream
  [^InputStream input]
  (let [hash (MessageDigest/getInstance "SHA-256")
        buffer (byte-array 8192)]
    (loop []
      (let [n (.read input buffer)]
        (when (pos? n)
          (.update hash buffer 0 n)
          (recur))))
    (.digest hash)))

(defmethod hash-sha256 :default
  [input]
  (throw (ex-info "Unsupported input for calculating hash. Use String or InputStream."
                  {:input-type (str (type input))})))

(def ^:no-doc digits
  (char-array "0123456789abcdef"))

(defn ^:no-doc hex-encode
  [bytes]
  (->> bytes
       (mapcat #(list (get digits (bit-shift-right (bit-and 0xF0 %) 4))
                      (get digits (bit-and 0x0F %))))))

(defn ^:no-doc hex-encode-str
  [bytes]
  (->> bytes
       (hex-encode)
       (apply str)))

;; Clojure implementation of signature
;; https://gist.github.com/souenzzo/21f3e81b899ba3f04d5f8858b4ecc2e9
;; https://github.com/joseferben/clj-aws-sign/ (ring middelware)

(defn ^:no-doc hmac-sha-256
  [key ^String data]
  (let [algo "HmacSHA256"
        mac (Mac/getInstance algo)]
    (.init mac (SecretKeySpec. key algo))
    (.doFinal mac (.getBytes data "UTF-8"))))

(defn ^:no-doc char-range
  [start end]
  (map char (range (int start) (inc (int end)))))

(def ^:no-doc unreserved-chars
  (->> (concat '(\- \. \_ \~)
               (char-range \A \Z)
               (char-range \a \z)
               (char-range \0 \9))
       (into #{})))

(def ^:no-doc url-unreserved-chars
  (conj unreserved-chars \/))

(defn ^:no-doc encode
  [skip-chars c]
  (if (skip-chars c)
    c
    (let [byte-val (int c)]
      (format "%%%X" byte-val))))

(defn ^:no-doc uri-encode
  [skip-chars uri]
  (->> uri
       (map (partial encode skip-chars))
       (apply str)))

(def ^DateTimeFormatter ^:no-doc formatter
  (-> (DateTimeFormatter/ofPattern "yyyyMMdd'T'HHmmss'Z'")
      (.withZone (ZoneId/from ZoneOffset/UTC))))

(defn ^:no-doc compute-signature
  [{:keys [credentials str-to-sign region service short-date]}]
  (-> (str "AWS4" (:aws/secret-access-key credentials))
      (.getBytes)
      (hmac-sha-256 short-date)
      (hmac-sha-256 region)
      (hmac-sha-256 service)
      (hmac-sha-256 "aws4_request")
      (hmac-sha-256 str-to-sign)
      hex-encode-str))

(def ^:no-doc algorithm
  "AWS4-HMAC-SHA256")

;; To override values for a set of response headers in the GetObject response,
;; you can use the following query parameters in the request.
;; https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html

(def ^:no-doc response-header-types
  #{"response-cache-control"
    "response-content-disposition"
    "response-content-encoding"
    "response-content-language"
    "response-content-type"
    "response-expires"})

(defn ^:no-doc ->query-str
  [query-params]
  (->> query-params
       (map (fn [[k v]] [(uri-encode unreserved-chars k) (uri-encode unreserved-chars v)]))
       (into (sorted-map)) ; sort AFTER URL encoding
       (map (fn [[k v]] (str k "=" v)))
       (str/join "&")))

(defn ^:no-doc ->headers-str
  [headers]
  (->> headers
       (map (fn [[k v]] (str k ":" (some-> v str/trim) "\n")))
       (apply str)))

(defn hash-input
  "Takes input as either `String` or `InputStream`
   to calculate and return a hash."
  [payload]
  (some-> (or payload "")
          (hash-sha256)
          (hex-encode-str)))

(defn canonical-request-str
  "Generates a canonical request string as specified here:
   https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html#canonical-request"
  [canonical-url {:keys [content-sha256 method query-params signed-headers] :as _opts}]
  (let [sorted-signed-headers (->> signed-headers
                                   (map (fn [[k v]] [(str/lower-case k) v]))
                                   (into (sorted-map)))]
    (str (-> (or method :get) name str/upper-case) "\n"
         (uri-encode url-unreserved-chars canonical-url) "\n"
         (->query-str query-params) "\n"
         (->headers-str sorted-signed-headers) "\n"
         (str/join ";" (map key sorted-signed-headers)) "\n"
         (or content-sha256 (hash-input nil)))))

(defn signature
  "AWS specification: https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html

   Inspired by https://gist.github.com/souenzzo/21f3e81b899ba3f04d5f8858b4ecc2e9"
  [credentials canonical-url {:keys [scope timestamp region service] :as opts}]
  (let [canonical-request (canonical-request-str canonical-url (select-keys opts [:content-sha256 :method :query-params :signed-headers]))
        str-to-sign (str algorithm "\n"
                         timestamp "\n"
                         scope "\n"
                         (hex-encode-str (hash-sha256 canonical-request)))]
    (compute-signature {:credentials credentials
                        :str-to-sign str-to-sign
                        :region region
                        :service service
                        :short-date (subs timestamp 0 8)})))

(defn ^:no-doc get-query-params
  [params-str]
  (when (seq params-str)
    (->> (str/split params-str #"&")
         (map (fn [param]
                (let [[k v] (str/split param #"=" 2)]
                  ;; ensure vector with exactly 2 elements (key/value) for `into` to work
                  [k v])))
         (into (sorted-map)))))

(defn sign-request
  "Takes a client and a Ring style request map.
   Returns an enriched Ring style map with the required headers
   needed for AWS signing."
  ([client {:keys [body headers method url] :as request}
    {:keys [ref-time region service payload-hash]
     :or {region (:region client)
          service "execute-api"
          ref-time (Date.)}
     :as _opts}]
   (let [credentials (:credentials client)
         url-obj (URL. url)
         port (.getPort url-obj)
         host (cond-> (.getHost url-obj)
                (pos? port) (str ":" port))
         timestamp (.format formatter (.toInstant ^Date ref-time))
         scope (str (subs timestamp 0 8) "/" region "/" service "/aws4_request")
         content-sha256 (or payload-hash
                            (when (string? body) ; protect against consuming InputStreams which can only be consumed once.
                              (hash-input body)))
         signed-headers (-> headers
                            (assoc "Host" host
                                   "x-amz-content-sha256" (or content-sha256 "UNSIGNED-PAYLOAD")
                                   "x-amz-date" timestamp
                                   "x-amz-security-token" (:aws/session-token credentials)))
         signature-str (signature credentials
                                  (.getPath url-obj)
                                  {:scope scope
                                   :timestamp timestamp
                                   :region region
                                   :service service
                                   :method method
                                   :signed-headers signed-headers
                                   :query-params (get-query-params (.getQuery url-obj))
                                   :content-sha256 content-sha256})]
     (-> request
         (assoc :headers (dissoc signed-headers "Host")) ; overwrite headers to include necessary x-amz-* ones
         (update :headers assoc
                 "Authorization" (str algorithm " Credential=" (:aws/access-key-id credentials) "/" scope ", "
                                      "SignedHeaders=" (str/join ";" (map key signed-headers)) ", "
                                      "Signature=" signature-str))))))

(defn presign
  "Take an URL for a S3 object and returns a string with a presigned URL
   for that particular object.
   Takes the following options (a map) as the last argument,
   the map value shows the default values:

       {:ref-time (java.util.Date.)    ; timestamp incorporated into the signature
        :expires \"3600\"              ; signature expires x seconds after ref-time
        :region \"us-east-1\"          ; signature locked to AWS region
        :method :get                   ; http method the url is to be called with
        :override-response-headers {}} ; override response headers

   By default credentials are read from standard AWS location."
  ([credentials url]
   (presign credentials url {}))
  ([credentials url {:keys [ref-time region expires method override-response-headers]
                     :or {ref-time (Date.) region "us-east-1" expires "3600" override-response-headers {}}}]
   (let [url-obj (URL. url)
         port (.getPort url-obj)
         host (cond-> (.getHost url-obj)
                (pos? port) (str ":" port))
         service "s3"
         timestamp (.format formatter (.toInstant ^Date ref-time))
         scope (str (subs timestamp 0 8) "/" region "/" service "/aws4_request")
         extra-query-params (-> override-response-headers
                                (update-keys (comp str/lower-case name))
                                (select-keys response-header-types))
         query-params (conj {"X-Amz-Algorithm" algorithm
                             "X-Amz-Credential" (str (:aws/access-key-id credentials) "/" scope)
                             "X-Amz-Date" timestamp
                             "X-Amz-SignedHeaders" "host"}
                            (when-let [session-token (:aws/session-token credentials)]
                              ["X-Amz-Security-Token" session-token])
                            (when expires
                              ["X-Amz-Expires" expires])
                            extra-query-params)
         signature (signature credentials
                              (.getPath url-obj)
                              {:timestamp timestamp
                               :region region
                               :service service
                               :scope scope
                               :method method
                               :query-params query-params
                               :signed-headers {"host" host}})]
     (str (.getProtocol url-obj) "://" host (.getPath url-obj) "?"
          (->query-str query-params)
          "&X-Amz-Signature=" signature))))

(defn ^:no-doc construct-endpoint-str
  "Helper function to deal with the endpoints data structure from Cognitect client
   which can be quite confusing."
  ;; to keyword :protocol (singular) and :port only seems to exist
  ;; when :endpoint-override is used to set up the client
  ;; Also, :protocol is a keyword while :protocols contain a vector of strings
  ;; On top there seems to be a region on both the client (root) and inside endpoint
  [{:keys [hostname protocols protocol region port] :as _endpoint}]
  (str (or (when protocol (name protocol))
           (-> protocols sort last)) ; sort to prefer https
       "://" (if (= "s3.amazonaws.com" hostname)
               (str/replace hostname #"^s3\." (str "s3." region "."))
               (str hostname (when port (str ":" port))))
       "/"))

(defn generate-presigned-url
  "Takes client, bucket name, object key and an options map
   with the following default values:

       {:path-style false    ; path-style is the 'old way' of URL's
        :endpoint nil}       ; alternative endpoint eg. \"http://localhost:9000\"

   The options map is 'forwarded' to `presign`,
   see that function for more relevant options.
   Returns a presigned URL."
  [client bucket object-key {:keys [endpoint path-style region] :as opts}]
  (let [endpoint-str (or endpoint
                         (construct-endpoint-str (:endpoint client)))
        url (-> (if path-style
                  (str endpoint-str bucket "/")
                  (str/replace endpoint-str #"://" (str "://" bucket ".")))
                (str object-key))]
    (presign (:credentials client) url (assoc opts :region (or region (:region client))))))
