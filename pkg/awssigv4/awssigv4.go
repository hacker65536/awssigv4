package awssigv4

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	// Algorithm is  AWS4-HMAC-SHA256
	algorithm = "AWS4-HMAC-SHA256"
	// SpecialTerminationString is aws4_request
	specialTerminationString = "aws4_request"

	apisVersion = map[string]string{
		"ec2": "2016-11-15",
		"sts": "2011-06-15",
		"rds": "2014-10-31",
	}
)

// AWSSigv4 is hoge
type AWSSigv4 struct {
	Algorithm                string
	SpecialTerminationString string
	Svc                      string
	Region                   string
	URI                      string
	Method                   string
	Headers                  map[string]string
	Payload                  string
	QueryString              string
	RequestDateTime          string
	AWSDomain                string
	Scheme                   string
	Action                   string
}

// New  is hogehoge
func New() *AWSSigv4 {

	scheme := "https"
	method := "GET"
	region := "us-east-1"
	uri := "/"
	svc := "sts"
	//queryString := "Action=GetCallerIdentity"
	queryString := ""
	action := "get-caller-identity"
	payload := ""
	awsDomain := "amazonaws.com"
	return &AWSSigv4{
		Algorithm:                algorithm,
		SpecialTerminationString: specialTerminationString,
		Region:                   region,
		Svc:                      svc,
		RequestDateTime:          createRequestDateTime(),
		Method:                   method,
		URI:                      uri,
		QueryString:              queryString,
		Payload:                  payload,
		AWSDomain:                awsDomain,
		Scheme:                   scheme,
		Action:                   action,
	}
}

func sign(k string, d string) []byte {
	nhmac := hmac.New(sha256.New, []byte(k))
	nhmac.Write([]byte(d))
	nhmacSum := nhmac.Sum(nil)
	return nhmacSum
}

func kebabToCamelCase(kebab string) (camelCase string) {
	isToUpper := true
	for _, runeValue := range kebab {
		if isToUpper {
			camelCase += strings.ToUpper(string(runeValue))
			isToUpper = false
		} else {
			if runeValue == '-' {
				isToUpper = true
			} else {
				camelCase += string(runeValue)
			}
		}
	}

	// for rds API
	reg := regexp.MustCompile(`Db`)
	camelCase = reg.ReplaceAllString(camelCase, "DB")
	return
}

// CreateURL is a func returns the URL which generated from parameter
func (a *AWSSigv4) CreateURL() string {

	qs := a.QueryString
	ver := apisVersion[a.Svc]
	hostname := a.Svc + "." + a.Region + "." + a.AWSDomain

	url := a.Scheme + "://" + hostname + a.URI
	if a.Method == "GET" {
		if qs != "" {
			qs += "&"
		}
		qs += "Action=" + kebabToCamelCase(a.Action)
		qs += "&Version=" + ver
		url += "?" + qs

		a.QueryString = qs
	}

	return url
}

func (a *AWSSigv4) createCanonicalRequest() string {

	creq := a.Method + "\n"
	creq += a.createCanonicalURI() + "\n"
	creq += a.createCanonicalQueryString() + "\n"

	cheaders, sheaders := a.createCanonicalHeaders()

	creq += cheaders + "\n"
	creq += sheaders + "\n"
	creq += a.createHashedPayload()

	return creq
}

func (a *AWSSigv4) createCanonicalURI() string {
	uriseg := strings.Split(a.URI, "/")
	ary := []string{}

	for _, v := range uriseg {

		v2 := v
		if v != "" {
			v2 = url.PathEscape(v2)
			v2 = url.PathEscape(v2)
		}
		ary = append(ary, v2)
	}
	curi := strings.Join(ary, "/")
	return curi
}

func (a *AWSSigv4) createCanonicalQueryString() string {
	// https://stackoverflow.com/questions/15854017/what-rfc-defines-arrays-transmitted-over-http
	// no idea for restruct of array of paramter

	// Replace semicolons , because url.ParseQuery split querys by ampersands or semicolons
	q := strings.ReplaceAll(a.QueryString, ";", "%3B")

	m, err := url.ParseQuery(q)
	m1 := make([]string, len(m))
	if err != nil {
		fmt.Println(err)
	}
	i := 0
	for k := range m {
		m1[i] = k
		i++
	}
	sort.Strings(m1)

	cqs := []string{}
	for i := 0; i < len(m1); i++ {
		k := url.QueryEscape(m1[i])
		v := url.QueryEscape(m[m1[i]][0])
		o := k + "=" + v
		cqs = append(cqs, o)
	}

	return strings.Join(cqs, "&")
}

func (a *AWSSigv4) createCanonicalHeaders() (string, string) {

	headers := a.Headers
	cheaders := ""
	m1 := make([]string, len(headers))
	m2 := make(map[string]string, len(headers))

	i := 0
	for k, v := range headers {
		hn := strings.ToLower(k)
		m1[i] = hn
		m2[hn] = v
		i++
	}

	sort.Strings(m1)

	for i := 0; i < len(m1); i++ {
		cheaders += m1[i] + ":" + strings.Join(strings.Fields(strings.TrimSpace(m2[m1[i]])), " ") + "\n"
	}

	sheaders := strings.Join(m1, ";")
	return cheaders, sheaders
}

func (a *AWSSigv4) createHashedPayload() string {
	if a.Method == "POST" {
		ver := apisVersion[a.Svc]
		a.Payload = "Action=" + kebabToCamelCase(a.Action) + "&Version=" + ver
	}
	p := a.Payload
	hash := sha256.Sum256([]byte(p))
	return strings.ToLower(hex.EncodeToString(hash[:]))
}

func (a *AWSSigv4) createStringToSign(credentialScope, canonicalRequest string) string {

	s := getAlgorithm() + "\n"
	s += a.RequestDateTime + "\n"
	s += credentialScope + "\n"
	hash := sha256.Sum256([]byte(canonicalRequest))
	s += hex.EncodeToString(hash[:])

	return s
}

func createRequestDateTime() string {
	return time.Now().UTC().Format("20060102T150405Z")
}

func getAlgorithm() string {
	return algorithm
}

func (a *AWSSigv4) createCredentialScope() string {
	return a.RequestDateTime[:8] + "/" + a.Region + "/" + a.Svc + "/" + a.SpecialTerminationString
}

func (a *AWSSigv4) createSignatureKey(secret string) []byte {
	kd := sign("AWS4"+secret, a.RequestDateTime[:8])
	kr := sign(string(kd), a.Region)
	ks := sign(string(kr), a.Svc)
	sig := sign(string(ks), a.SpecialTerminationString)

	return sig
}

func (a *AWSSigv4) createSignature(sigkey, sigstr string) string {
	return hex.EncodeToString(sign(string(sigkey), sigstr))
}

// CreateAuthorizationHeader is create authrozation header for prepare to call rest api
func (a *AWSSigv4) CreateAuthorizationHeader(keyid, secret string) string {
	_, shs := a.createCanonicalHeaders()

	sigkey := a.createSignatureKey(secret)
	cs := a.createCredentialScope()
	cr := a.createCanonicalRequest()
	sigstr := a.createStringToSign(cs, cr)

	sig := a.createSignature(string(sigkey), sigstr)

	authheader := a.Algorithm + " "
	authheader += "Credential=" + keyid + "/"
	authheader += a.createCredentialScope() + ", "
	authheader += "SignedHeaders=" + shs + ", "
	authheader += "Signature=" + sig

	return authheader
}
