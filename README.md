# aws-simple-sign

A Clojure library to sign requests for AWS and generating presigned URLS.
The library have very few and very simple dependencies.

## Usage

To generate a presigned URL for a S3 object:

    (aws/presign "https://s3.us-west-1.amazonaws.com/somebucket/someobject.txt"
                 {:region "us-west-1"})
