# aws-simple-sign

A Clojure library to sign requests for AWS and generating presigned URLS.
The library have very few and very simple dependencies.

## Usage

To generate a presigned URL for a S3 object:

    (aws/presign "https://s3.us-west-1.amazonaws.com/somebucket/someobject.txt"
                 {:region "us-west-1"})


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
