# AWS Sig version4
example of AWS API implementation with go 



```console
$ awssigv4 ec2 describe-vpcs
GET /?Action=DescribeVpcs&Version=2016-11-15 HTTP/1.1
Host: ec2.us-east-2.amazonaws.com
User-Agent: Go-http-client/1.1
Authorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20210213/us-east-2/ec2/aws4_request, SignedHeaders=host;x-amz-date, Signature=8cf6d0e3ca017p014ec2b82692d5d11f77d7ea8053a0a33e1eb8df0cef608ac9
X-Amz-Date: 20210213T153908Z
Accept-Encoding: gzip

HTTP/1.1 200 OK
Transfer-Encoding: chunked
Cache-Control: no-cache, no-store
Content-Type: text/xml;charset=UTF-8
Date: Sat, 13 Feb 2021 15:39:08 GMT
Server: AmazonEC2
Strict-Transport-Security: max-age=31536000; includeSubDomains
Vary: accept-encoding
X-Amzn-Requestid: 8d2ff4a1-a389-857f-ae87-aa4b8b23a4a9
--snip---
```
