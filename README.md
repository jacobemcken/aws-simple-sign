# aws-simple-sign

A Clojure library for pre-signing S3 URLs and signing HTTP requests for AWS.
The library only depends on Java core (no external Java dependencies),
making it lightweight.

[![bb compatible](https://raw.githubusercontent.com/babashka/babashka/master/logo/badge.svg)](https://babashka.org)

If you stumble upon problems,
feel free to reach out either by creating an issue
or ping me via Clojurian Slack.


## Usage

Include the dependency in your project:

[![Clojars Project](https://img.shields.io/clojars/v/dk.emcken/aws-simple-sign.svg?include_prereleases)](https://clojars.org/dk.emcken/aws-simple-sign)


### AWS Credentials

The library needs "client" information containing credentials etc.

Both [Cognitect AWS API client][1] and [awyeah][2] can produce compatible clients.
These clients will look for credentials in all the usual places
honoring how [AWS specific environment variables][3] and configuration,
except for endpoint which needs to be provided in code (see `:endpoint-override` below).

> 💡 Only `awyeah-api` works with [Babashka][4] at the time of writing.

The following example uses the `awyeah-api` lib.
```clojure
(require '[com.grzm.awyeah.client.api :as aws])

(def client
  (aws/client {:api :s3
           ;; :endpoint-override is commented out
           ;; and usually only relevant for non-Amazon or local setups
           #_#_:endpoint-override {:protocol :http
                                   :hostname "localhost"
                                   :port 9000}))
```

Alternatively, the same data structure can be provided manually:

```clojure
(def client
  {:credentials #:aws{:access-key-id "some-access-key"
                      :secret-access-key "wild_secr3t"
                      :session-token "FwoG..."}
   :region "us-east-1"
   :endpoint {:protocol :https
              :hostname "s3.amazonaws.com"}})
```


### Presigned URL's

To generate a pre-signed URL for a S3 object:

```clojure
(require '[aws-simple-sign.core :as aws])

(aws/generate-presigned-url client "somebucket" "someobject.txt" {})
"https://somebucket.s3.us-east-1.amazonaws.com/someobject.txt?X-Amz-Security-Token=FwoG..."
```

By default, the URLs returned will use "virtual hosted-style".
But having an S3 bucket with dots (`.`) in the name, the SSL certificate cannot be verified.
This can cause many types of errors depending on the code consuming the URL, but one could be:

> No subject alternative DNS name matching

To avoid this problem, it is possible to generate URLs using "path style" instead.
This, of course, has its own disadvantages
but can be a way out when it is impossible to rename the bucket.

```clojure
(aws/generate-presigned-url client "somebucket" "someobject.txt" {:path-style true})
"https://s3.us-east-1.amazonaws.com/somebucket/someobject.txt?X-Amz-Security-Token=FwoG..."
```

For more information about "virtual hosted vs. path style" in the official announcements:
- 08 MAY 2019 https://aws.amazon.com/blogs/aws/amazon-s3-path-deprecation-plan-the-rest-of-the-story/
- 22 SEP 2020 https://aws.amazon.com/blogs/storage/update-to-amazon-s3-path-deprecation-plan/


### Signed HTTP requests

The following example illustrates how signing can be used from within a Babashka script:

```clojure
(require '[aws-simple-sign.core :as aws])
(require '[babashka.http-client :as http])

(let [signed-request (-> {:url "https://someurl/some-api-endpoint"
                          :method :post
                          :headers {"accept" "application/json"}
                          :body "{\"somekey\": \"with some value\"}"}
                          (aws/sign-request {:region "us-west-1"}))]

    (http/post (:url signed-request)
               (-> signed-request
                   (select-keys [:body :headers]))))
```

[1]: https://github.com/cognitect-labs/aws-api
[2]: https://github.com/grzm/awyeah-api
[3]: https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html
[4]: https://github.com/babashka/babashka
