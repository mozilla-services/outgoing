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
	// Test URL no query string
	hSig := getHmac("http://www.mozilla.org/", "secret")

	rec := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/v1/"+hSig+"/http%3A//www.mozilla.org/", nil)
	if err != nil {
		t.Fatalf("hmac: %s err: %v", hSig, err)
	}
	readReq(rec, req)
	if rec.Code != 200 {
		t.Errorf("Expected %d, returned %d. hmac: %s", 200, rec.Code, hSig)
	}
	if !strings.Contains(rec.Body.String(), "http://www.mozilla.org/") {
		t.Errorf("http://www.mozilla.org/ is not in %s.", rec.Body.String())
	}

	// Test urls with & character
	hSig = getHmac("http://www.mozilla.org/?foo=bar&boo=baz", "secret")

	rec = httptest.NewRecorder()
	req, err = http.NewRequest("GET", "/v1/"+hSig+"/http%3A//www.mozilla.org/%3Ffoo=bar&boo=baz", nil)
	if err != nil {
		t.Fatalf("hmac: %s err: %v", hSig, err)
	}
	readReq(rec, req)
	if rec.Code != 200 {
		t.Errorf("Expected %d, returned %d. hmac: %s", 200, rec.Code, hSig)
	}
	if !strings.Contains(rec.Body.String(), `href="http://www.mozilla.org/?foo=bar&amp;boo=baz"`) {
		t.Errorf("http://www.mozilla.org/?foo=bar&amp;boo=baz is not in %s.", rec.Body.String())
	}

	// Test bad secret
	hSig = getHmac("http://www.mozilla.org/", "badsecret")

	rec = httptest.NewRecorder()
	req, err = http.NewRequest("GET", "/v1/"+hSig+"/http%3A//www.mozilla.org/", nil)
	if err != nil {
		t.Fatal(err)
	}
	readReq(rec, req)
	if rec.Code != 400 {
		t.Errorf("Expected %d, returned %d.", 400, rec.Code)
	}

	hSig = getHmac("javascript:alert()", "badsecret")

	rec = httptest.NewRecorder()
	req, err = http.NewRequest("GET", "/v1/"+hSig+"/javascript:alert()", nil)
	if err != nil {
		t.Fatal(err)
	}
	readReq(rec, req)
	if rec.Code != 400 {
		t.Errorf("Expected %d, returned %d.", 400, rec.Code)
	}
}
