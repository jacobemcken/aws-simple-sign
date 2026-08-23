(ns aws-simple-sign.core-test
  (:require [clojure.test :refer [deftest is testing]]
            [aws-simple-sign.core :as sut])
  (:import (java.io ByteArrayInputStream)))

(def credentials
  {:aws/access-key-id "AKIAIOSFODNN7EXAMPLE"
   :aws/secret-access-key "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"})

;; Testing example from: https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
(deftest sign
  (is (= "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
         (sut/signature credentials
                        "/test.txt"
                        {:timestamp "20130524T000000Z"
                         :region "us-east-1"
                         :service "s3"
                         :scope "20130524/us-east-1/s3/aws4_request"
                         :content-sha256 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                         :signed-headers {"host" "examplebucket.s3.amazonaws.com"
                                          "range" "bytes=0-9"
                                          "x-amz-content-sha256" "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                                          "x-amz-date" "20130524T000000Z"}}))))

(deftest canonical-request-generation
  (testing "Exact example from official documentation"
    (let [canonical-request (sut/canonical-request-str
                             "/test.txt"
                             {:signed-headers {"Host" "examplebucket.s3.amazonaws.com"
                                               "Range" "bytes=0-9"
                                               "x-amz-content-sha256" "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                                               "X-AMZ-date" "20130524T000000Z"}
                              :content-sha256 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"})]
      (is (= "GET
/test.txt

host:examplebucket.s3.amazonaws.com
range:bytes=0-9
x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
x-amz-date:20130524T000000Z

host;range;x-amz-content-sha256;x-amz-date
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
             canonical-request))
      (is (= "7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972"
             (-> canonical-request
                 (sut/hash-sha256)
                 (sut/hex-encode-str))))))

  (testing "Sorting of query params"
    (is (= "GET
/test.txt
marker=someMarker&max-keys=20&prefix=somePrefix
host:examplebucket.s3.amazonaws.com

host
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
           (sut/canonical-request-str
            "/test.txt"
            {:method :get
             :signed-headers {"Host" "examplebucket.s3.amazonaws.com"}
             :query-params {"prefix" "somePrefix" ;notice the unsorted order
                            "marker" "someMarker"
                            "max-keys" "20"}}))))

  (testing "UNSIGNED-PAYLOAD"
    (is (= "GET
/test.txt

host:examplebucket.s3.amazonaws.com
x-amz-content-sha256:UNSIGNED-PAYLOAD

host;x-amz-content-sha256
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
           (sut/canonical-request-str
            "/test.txt"
            {:method :get
             :signed-headers {"Host" "examplebucket.s3.amazonaws.com"
                              "x-amz-content-sha256" "UNSIGNED-PAYLOAD"}
             :content-sha256 nil})))))

(deftest hashing-payloads
  (testing "hashing an empty payload"
    (is (= "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
           (sut/hash-input "")))
    (is (= "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
           (sut/hash-input nil))))
  (testing "hasing 'user@example.com'"
    ;; Example taken from: https://stackoverflow.com/questions/71042721/how-to-base64-encode-a-sha256-hex-character-string
    (is (= "b4c9a289323b21a01c3e940f150eb9b8c542587f1abfd8f0e1cc1ffc5e475514"
           (sut/hash-input "user@example.com"))))
  (testing "hasing 'user@example.com'"
    ;; Example taken from: https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
    (is (= "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072"
           (sut/hash-input "Welcome to Amazon S3."))))
  (testing "hasing a resetable InputStream"
    (is (= "b4c9a289323b21a01c3e940f150eb9b8c542587f1abfd8f0e1cc1ffc5e475514"
           (sut/hash-input (ByteArrayInputStream. (.getBytes "user@example.com")))))))

(deftest url-encoding-with-special-characters-and-spaces
  (testing "UTF-8 encoding of special characters and spaces"
    (is (= "/test%20%C3%A6%C3%B8%C3%A5.txt"
           (sut/uri-encode sut/url-unreserved-chars "/test æøå.txt")))))

(deftest as-url
  (testing "virtual-host style: bucket prefixed to hostname"
    (is (= "http://bucket.localhost:9000/my%20file.txt"
           (sut/as-url "http://localhost:9000" "bucket" "my file.txt" false))))

  (testing "path style: bucket as a path segment"
    (is (= "http://localhost:9000/bucket/my%20file.txt"
           (sut/as-url "http://localhost:9000" "bucket" "my file.txt" true))))

  (testing "special characters in object key are escaped"
    (is (= "http://bucket.localhost:9000/my%20file%20%23%C3%A6.txt"
           (sut/as-url "http://localhost:9000" "bucket" "my file #æ.txt" false))))

  (testing "slashes in object key are preserved (folder-style keys)"
    (is (= "http://bucket.localhost:9000/folder/file.txt"
           (sut/as-url "http://localhost:9000" "bucket" "folder/file.txt" false))))

  (testing "works with https endpoints"
    (is (= "https://bucket.s3.eu-west-1.amazonaws.com/file.txt"
           (sut/as-url "https://s3.eu-west-1.amazonaws.com" "bucket" "file.txt" false))))

  (testing "trailing slash on endpoint is optional"
    (is (= (sut/as-url "http://localhost:9000" "bucket" "file.txt" false)
           (sut/as-url "http://localhost:9000/" "bucket" "file.txt" false)))))
