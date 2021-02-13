package awssigv4

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"testing"
)

func TestSign(t *testing.T) {
	key := "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	skey := "AWS4" + key
	dateStamp := "20120215"

	s := sign(skey, dateStamp)
	output := hex.EncodeToString(s)

	expected := "969fbb94feb542b71ede6f87fe4d5fa29c789342b0f407474670f0c2489e0a0d"

	if output != expected {
		t.Errorf("%v\n%v", output, expected)
	}
}

func TestCreateCanonicalURI(t *testing.T) {

	a := AWSSigv4{
		URI: "/documents and settings/",
	}

	output := a.createCanonicalURI()
	expected := `/documents%2520and%2520settings/`
	if output != expected {
		t.Errorf("\n%v\n%v", output, expected)
	}

}

func TestCreateCanonicalQueryStrings(t *testing.T) {

	q := "Action=ListUsers&X-Amz-Algorithm=AWS4-HMAC-SHA256&Version=2010-05-08"
	q += "&X-Amz-Date=20150830T123600Z&X-Amz-SignedHeaders=content-type;host;x-amz-date"
	q += "&X-Amz-Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request"
	a := AWSSigv4{
		QueryString: q,
	}

	output := a.createCanonicalQueryString()

	// keep oder
	expected := "Action=ListUsers&Version=2010-05-08"
	expected += "&X-Amz-Algorithm=AWS4-HMAC-SHA256"
	expected += "&X-Amz-Credential=AKIDEXAMPLE%2F20150830%2Fus-east-1%2Fiam%2Faws4_request"
	expected += "&X-Amz-Date=20150830T123600Z&X-Amz-SignedHeaders=content-type%3Bhost%3Bx-amz-date"

	if output != expected {
		t.Errorf("\n%v\n%v", output, expected)
	}
}

func TestCreateCanonicalHeaders(t *testing.T) {
	hs := map[string]string{
		"Host":         "iam.amazonaws.com",
		"Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
		"My-header1":   "    a   b   c  ",
		"X-Amz-Date":   "20150830T123600Z",
		"My-Header2":   `    "a   b   c"  `,
	}

	a := AWSSigv4{
		Headers: hs,
	}
	output, _ := a.createCanonicalHeaders()

	expected := "content-type:application/x-www-form-urlencoded; charset=utf-8\n"
	expected += "host:iam.amazonaws.com\n"
	expected += "my-header1:a b c\n"
	expected += "my-header2:\"a b c\"\n"
	expected += "x-amz-date:20150830T123600Z\n"

	if output != expected {
		t.Errorf("\n%v\n%v", output, expected)
	}
}

func TestCreateHashedPayload(t *testing.T) {

	p := ""

	a := AWSSigv4{
		Payload: p,
	}
	output := a.createHashedPayload()
	expected := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	if output != expected {
		t.Errorf("\n%v\n%v", output, expected)
	}

}

func TestCreateCanonicalRequest(t *testing.T) {

	method := "GET"
	uri := "/"
	queryString := "Action=ListUsers&Version=2010-05-08"

	headers := map[string]string{
		"Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
		"X-Amz-Date":   "20150830T123600Z",
		"Host":         "iam.amazonaws.com",
	}

	payload := ""

	a := AWSSigv4{
		Method:      method,
		URI:         uri,
		QueryString: queryString,
		Headers:     headers,
		Payload:     payload,
	}

	output := a.createCanonicalRequest()

	expected := "GET\n"
	expected += "/\n"
	expected += "Action=ListUsers&Version=2010-05-08\n"
	expected += "content-type:application/x-www-form-urlencoded; charset=utf-8\n"
	expected += "host:iam.amazonaws.com\n"
	expected += "x-amz-date:20150830T123600Z\n"
	expected += "\n"
	expected += "content-type;host;x-amz-date\n"
	expected += "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	if output != expected {
		t.Errorf("\n%v\n%v", output, expected)
	}

	expectedH := "f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59"

	s := sha256.Sum256([]byte(expected))
	h := hex.EncodeToString(s[:])
	if h != expectedH {
		t.Errorf("\n%v\n%v", h, expectedH)
	}
}

func TestGetAlgorithm(t *testing.T) {
	output := getAlgorithm()
	expected := "AWS4-HMAC-SHA256"
	if output != expected {
		t.Errorf("\n%v\n%v", output, expected)
	}
}

func TestCreateRequestDateTime(t *testing.T) {
	output := createRequestDateTime()

	reg := regexp.MustCompile(`\d{8}T\d{6}Z$`)

	if !reg.MatchString(output) {
		t.Errorf("\n%v", output)
	}
	//	t.Log(output)
}

func TestCreateCredentialScope(t *testing.T) {

	datetime := "20150830T123600Z"
	svc := "iam"
	region := "us-east-1"

	a := AWSSigv4{
		RequestDateTime:          datetime,
		Svc:                      svc,
		Region:                   region,
		SpecialTerminationString: "aws4_request",
	}
	output := a.createCredentialScope()

	expected := "20150830/us-east-1/iam/aws4_request"
	if output != expected {
		t.Errorf("\n%v\n%v", output, expected)
	}
}

func TestCreateStringToSign(t *testing.T) {
	d := "20150830T123600Z"
	region := "us-east-1"
	svc := "iam"
	qs := "Action=ListUsers&Version=2010-05-08"
	headers := map[string]string{
		"Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
		"X-Amz-Date":   "20150830T123600Z",
		"Host":         "iam.amazonaws.com",
	}
	payload := ""
	method := "GET"
	uri := "/"

	a := AWSSigv4{
		Method:                   method,
		URI:                      uri,
		RequestDateTime:          d,
		Region:                   region,
		Svc:                      svc,
		SpecialTerminationString: "aws4_request",
		QueryString:              qs,
		Headers:                  headers,
		Payload:                  payload,
		Algorithm:                "AWS4-HMAC-SHA256",
	}
	cs := a.createCredentialScope()
	//cs := "20150830/us-east-1/iam/aws4_request"

	cr := a.createCanonicalRequest()
	//cr := "GET\n"
	//cr += "/\n"
	//cr += "Action=ListUsers&Version=2010-05-08\n"
	//cr += "content-type:application/x-www-form-urlencoded; charset=utf-8\n"
	//cr += "host:iam.amazonaws.com\n"
	//cr += "x-amz-date:20150830T123600Z\n"
	//cr += "\n"
	//cr += "content-type;host;x-amz-date\n"
	//cr += "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	output := a.createStringToSign(cs, cr)
	expected := "AWS4-HMAC-SHA256\n"
	expected += "20150830T123600Z\n"
	expected += "20150830/us-east-1/iam/aws4_request\n"
	expected += "f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59"

	if output != expected {
		t.Errorf("\n%v\n%v", output, expected)
	}
}

func TestCreateSignatureKey(t *testing.T) {

	sec := "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	date := "20150830"
	region := "us-east-1"
	svc := "iam"
	a := AWSSigv4{
		RequestDateTime:          date,
		Region:                   region,
		Svc:                      svc,
		SpecialTerminationString: "aws4_request",
	}
	key := a.createSignatureKey(sec)
	output := hex.EncodeToString(key)
	expected := "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"

	if output != expected {
		t.Errorf("\n%v\n%v", output, expected)
	}
}

func TestCreateSignature(t *testing.T) {

	sec := "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	date := "20150830"
	region := "us-east-1"
	svc := "iam"

	a := AWSSigv4{
		RequestDateTime:          date,
		Region:                   region,
		Svc:                      svc,
		SpecialTerminationString: "aws4_request",
	}
	sigkey := a.createSignatureKey(sec)

	sigstr := "AWS4-HMAC-SHA256\n"
	sigstr += "20150830T123600Z\n"
	sigstr += "20150830/us-east-1/iam/aws4_request\n"
	sigstr += "f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59"

	sig := a.createSignature(string(sigkey), sigstr)

	if sig != "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7" {
		t.Errorf("\n%v", sig)
	}
}

func TestCreateAuthorizationHeader(t *testing.T) {

	key := "AKIDEXAMPLE"
	method := "GET"
	uri := "/"
	sec := "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	date := "20150830T123600Z"
	region := "us-east-1"
	svc := "iam"
	headers := map[string]string{
		"Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
		"X-Amz-Date":   "20150830T123600Z",
		"Host":         "iam.amazonaws.com",
	}
	qs := "Action=ListUsers&Version=2010-05-08"
	a := AWSSigv4{
		Method:                   method,
		URI:                      uri,
		Algorithm:                "AWS4-HMAC-SHA256",
		RequestDateTime:          date,
		Region:                   region,
		Svc:                      svc,
		SpecialTerminationString: "aws4_request",
		Headers:                  headers,
		QueryString:              qs,
	}
	output := "Authorization: "
	output += a.CreateAuthorizationHeader(key, sec)
	expected := "Authorization: "
	expected += "AWS4-HMAC-SHA256 "
	expected += "Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, "
	expected += "SignedHeaders=content-type;host;x-amz-date, "
	expected += "Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"

	if output != expected {
		t.Errorf("\n%v\n%v", output, expected)
	}
}

func TestCreateURL(t *testing.T) {
	svc := "ec2"
	region := "us-east-2"
	action := "describe-vpcs"
	scheme := "https"
	method := "GET"
	awsdomain := "amazonaws.com"
	uri := "/"

	a := AWSSigv4{
		Svc:       svc,
		Region:    region,
		Action:    action,
		Scheme:    scheme,
		Method:    method,
		AWSDomain: awsdomain,
		URI:       uri,
	}

	getoutput := a.CreateURL()
	getexpected := "https://ec2.us-east-2.amazonaws.com/?Action=DescribeVpcs&Version=2016-11-15"
	if getoutput != getexpected {
		t.Errorf("\n%v\n%v", getoutput, getexpected)
	}

	a.Method = "POST"
	postoutput := a.CreateURL()
	postexpected := "https://ec2.us-east-2.amazonaws.com/"
	if postoutput != postexpected {
		t.Errorf("\n%v\n%v", postoutput, postexpected)
	}
}

func TestKebabToCamelCase(t *testing.T) {
	output := kebabToCamelCase("get-caller-identity")
	expected := "GetCallerIdentity"
	if output != expected {
		t.Errorf("\n%v\n%v", output, expected)
	}
}
