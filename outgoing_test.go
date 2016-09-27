package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func init() {
	key := "secret"
	secretKey = &key
	*debugFlag = true
}

func TestValidateSig(t *testing.T) {
	url := "http://mozilla.org/en-US/"
	s1 := sha1.New()
	s1.Write([]byte("secret" + url))
	sig1 := fmt.Sprintf("%x", s1.Sum(nil))

	if !validateSig(url, sig1) {
		t.Errorf("url hash: %s did not match.", sig1)
	}

	s1 = sha1.New()
	s1.Write([]byte("badsecret" + url))
	sig1 = fmt.Sprintf("%x", s1.Sum(nil))

	if validateSig(url, sig1) {
		t.Errorf("bad url hash: %s matched.", sig1)
	}

	hSig := getHmac(url, "secret")

	if !validateSig(url, hSig) {
		t.Errorf("url hash: %s did not match.", hSig)
	}

	hSig = getHmac(url, "badsecret")

	if validateSig(url, hSig) {
		t.Errorf("bad url hash: %s matched.", hSig)
	}
}

func getHmac(url, key string) string {
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(url))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func TestReq(t *testing.T) {
	testCases := []struct {
		URL         string
		RequestPath string
		Expected    string
	}{
		{"http://www.mozilla.org/", "http%3A//www.mozilla.org/", `href="http://www.mozilla.org/"`},                                                                                                                                                                                              // Plain URL
		{"http://www.mozilla.org/?foo=bar&boo=baz", "http%3A//www.mozilla.org/%3Ffoo=bar&boo=baz", `href="http://www.mozilla.org/?foo=bar&amp;boo=baz`},                                                                                                                                         // URL with query params
		{"https://www.mozilla.org/?foo=bar&boo=baz", "https%3A//www.mozilla.org/%3Ffoo=bar&boo=baz", `href="https://www.mozilla.org/?foo=bar&amp;boo=baz`},                                                                                                                                      // URL with query params
		{`http://www.mozilla.org/"><script>alert()</script>`, `http%3A//www.mozilla.org/%22%3E%3Cscript%3Ealert%28%29%3C/script%3E%0A`, `<a href="http://www.mozilla.org/%22%3e%3cscript%3ealert%28%29%3c/script%3e">http://www.mozilla.org/&#34;&gt;&lt;script&gt;alert()&lt;/script&gt;</a>`}, // URL with crazy characters
	}
	for _, tc := range testCases {
		hSig := getHmac(tc.URL, "secret")

		rec := httptest.NewRecorder()
		req, err := http.NewRequest("GET", "/v1/"+hSig+"/"+tc.RequestPath, nil)
		if err != nil {
			t.Fatalf("hmac: %s err: %v", hSig, err)
		}
		readReq(rec, req)
		if rec.Code != 200 {
			t.Errorf("Expected %d, returned %d. hmac: %s", 200, rec.Code, hSig)
		}
		if !strings.Contains(rec.Body.String(), tc.Expected) {
			t.Errorf("%s is not in %s.", tc.Expected, rec.Body.String())
		}

	}

	failCases := []struct {
		URL         string
		RequestPath string
		Secret      string
	}{
		{"http://www.mozilla.org/", "http%3A//www.mozilla.org/", "badsecret"},
		{"javascript:alert()", "javascript:alert()", "secret"},
		{"www.mozilla.org", "www.mozilla.org", "secret"},
		{"ftp://www.mozilla.org", "ftp://www.mozilla.org", "secret"},
	}

	for _, tc := range failCases {
		hSig := getHmac(tc.URL, tc.Secret)
		rec := httptest.NewRecorder()
		req, err := http.NewRequest("GET", "/v1/"+hSig+"/"+tc.RequestPath, nil)
		if err != nil {
			t.Fatal(err)
		}
		readReq(rec, req)
		if rec.Code != 400 {
			t.Errorf("URL: %s Expected 400, returned %d.", tc.URL, rec.Code)
		}
	}
}
