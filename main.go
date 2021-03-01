package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"

	"github.com/hacker65536/awssigv4/pkg/awssigv4"
)

func main() {

	/*
		// 1 Create canonical request

		// 2 Create string to sign

		// 3 Create signature

		// 4 Create Authorization header to request
	*/

	key := os.Getenv("AWS_ACCESS_KEY_ID")
	sec := os.Getenv("AWS_SECRET_ACCESS_KEY")
	if key == "" || sec == "" {
		fmt.Println("no credentials")
		os.Exit(2)
	}
	//region := "us-east-2"
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-east-1"
	}
	//svc := "ec2"
	svc := os.Args[1]
	//act := "describe-vpcs"
	act := os.Args[2]
	method := "POST"

	aws4 := awssigv4.New()
	aws4.Method = method
	aws4.Region = region
	aws4.Svc = svc
	date := aws4.RequestDateTime
	headers := map[string]string{
		"Host":         svc + "." + region + "." + "amazonaws.com",
		"X-Amz-Date":   date,
		"Content-type": "application/x-www-form-urlencoded; charset=utf-8",
	}
	aws4.Headers = headers
	aws4.Action = act

	URL := aws4.CreateURL()
	auth := aws4.CreateAuthorizationHeader(key, sec)

	req, _ := http.NewRequest(method, URL, nil)
	if method == "POST" {
		//req, _ = http.NewRequest("POST", URL, bytes.NewBuffer([]byte(aws4.Payload)))

		req.Body = ioutil.NopCloser(strings.NewReader(aws4.Payload))
		req.ContentLength = int64(len(aws4.Payload))
	}

	req.Header.Set("Authorization", auth)
	req.Header.Set("X-Amz-Date", date)
	req.Header.Set("Content-type", "application/x-www-form-urlencoded; charset=utf-8")

	dumpReq, _ := httputil.DumpRequestOut(req, true)

	fmt.Printf("%s", dumpReq)
	client := new(http.Client)

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
	}

	dumpResp, _ := httputil.DumpResponse(resp, true)
	fmt.Printf("%s", dumpResp)

}
