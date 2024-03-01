# aws-simple-sign

A Clojure library to pre-signed URLs (S3) and sign HTTP requests for AWS.
The library only depends on Java core (no external Java dependencies),
making it fairly light.

The library might be somewhat naive.
I only took the implementation so far as I needed for myself.
But if you stumble upon problems
feel free to reach out either by creating an issue
or ping me via Clojurian Slack.


## Usage

### Presigned URL's

To generate a pre-signed URL for a S3 object:

```clojure
(require '[aws-simple-sign.core :as aws])

(aws/presign "https://s3.us-west-1.amazonaws.com/somebucket/someobject.txt"
             {:region "us-west-1"})
```

It is possible to choose whether to use "virtual hosted-style" URLs (the default) or "path-style URLs".
Path-style URLs are being deprecated (see links below),
but have the advantage of supporting bucket names which include dots (`.`) in the name,
which will otherwise cause URLs that cannot have their SSL certificate verified.

```clojure
(aws/generate-presigned-url "somebucket" "someobject.txt" {})
"https://somebucket.s3.eu-west-1.amazonaws.com/someobject.txt?X-Amz-Security-Token=FwoG..."

(aws/generate-presigned-url "somebucket" "someobject.txt" {:path-style true})
"https://s3.eu-west-1.amazonaws.com/somebucket/someobject.txt?X-Amz-Security-Token=FwoG..."
```

Official announcements:
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


## AWS Credentials

The library will look for credentials in all the usual places
honoring how [AWS specific environment variables][1] usually overwrite values.

Alternatively, provide credentials manually using the map structure:

```clojure
{:aws/access-key "AKIAIOSFODNN7EXAMPLE"
 :aws/secret-key "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
 :aws/token "aoGYXIvYXnzEOf/////////fEaDPDf......EXAMPLETOKEN="}
```

All three values (access key, secret and session token) must be available,
if not an exception with the message `AWS credentials missing or incomplete` is thrown.

Check the function `read-env-credentials` to get some insight into
how credentials are identified.

[1]: https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html
