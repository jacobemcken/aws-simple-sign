(defproject dk.emcken/aws-simple-sign "2.3.1"
  :description "A library to sign HTTP requests & generate presigned URL's for AWS"
  :url "https://github.com/jacobemcken/aws-simple-sign"
  :license {:name "The MIT License"
            :url "http://opensource.org/licenses/MIT"}
  :dependencies [[org.clojure/clojure "1.11.1"]]
  :profiles {:dev {:dependencies [[org.babashka/http-client "0.3.11"]
                                  [com.cognitect.aws/api "0.8.692"]
                                  [com.cognitect.aws/endpoints "1.1.12.701"]
                                  [com.cognitect.aws/s3 "868.2.1580.0"]]}})
