(defproject dk.emcken/aws-simple-sign "1.7.0-SNAPSHOT"
  :description "A library to sign HTTP requests & generate presigned URL's for AWS"
  :url "https://github.com/jacobemcken/aws-simple-sign"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.11.1"]
                 [org.clojure/tools.logging "1.3.0"]]
  :profiles {:dev {:dependencies [[org.babashka/http-client "0.3.11"]]}})
