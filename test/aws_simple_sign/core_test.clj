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

(deftest canonical-request-hash
  (is (= "7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972"
         (-> (str "GET\n"
                  "/test.txt\n"
                  "\n"
                  "host:examplebucket.s3.amazonaws.com\n"
                  "range:bytes=0-9\n"
                  "x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
                  "x-amz-date:20130524T000000Z\n"
                  "\n"
                  "host;range;x-amz-content-sha256;x-amz-date\n"
                  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
             (sut/hash-sha256)
             (sut/hex-encode-str)))))

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
  (testing "hasing a resetable InputStream"
    (is (= "b4c9a289323b21a01c3e940f150eb9b8c542587f1abfd8f0e1cc1ffc5e475514"
           (sut/hash-input (ByteArrayInputStream. (.getBytes "user@example.com")))))))
