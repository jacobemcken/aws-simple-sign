(ns aws-simple-sign.core-test
  (:require [clojure.test :refer [deftest is testing]]
            [aws-simple-sign.core :as sut]))

(def credentials
  {:aws/access-key "AKIAIOSFODNN7EXAMPLE"
   :aws/secret-key "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"})

;; Testing example from: https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
(deftest sign
  (is (= "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
         (sut/signature "/test.txt"
                        credentials
                        {:timestamp "20130524T000000Z"
                         :region "us-east-1"
                         :service "s3"
                         :scope "20130524/us-east-1/s3/aws4_request"
                         :content-sha256 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                         :signed-headers {"host" "examplebucket.s3.amazonaws.com"
                                          "range" "bytes=0-9"
                                          "x-amz-content-sha256" "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                                          "x-amz-date" "20130524T000000Z"}}))))

(deftest hashing-payloads
  (testing "hashing an empty payload"
    (is (= "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
           (sut/hashed-payload "")))
    (is (= "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
           (sut/hashed-payload nil)))))
