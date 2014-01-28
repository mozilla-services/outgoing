package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/hmac"
	"fmt"
	"net/http/httptest"
	"net/http"
	"strings"
	"testing"
)

func init() {
	key := "secret"
	secretKey = &key
}

func TestValidateSig(t *testing.T) {
	url := "http://mozilla.org/en-US/"
	s1 := sha1.New()
	s1.Write([]byte("secret"+ url))
	sig1 := fmt.Sprintf("%x", s1.Sum(nil))

	if !validateSig(url, sig1) {
		t.Errorf("url hash: %s did not match.", sig1)
	}

	s1 = sha1.New()
	s1.Write([]byte("badsecret"+ url))
	sig1 = fmt.Sprintf("%x", s1.Sum(nil))

	if validateSig(url, sig1) {
		t.Errorf("bad url hash: %s matched.", sig1)
	}

	h := hmac.New(sha256.New, []byte("secret"))
	h.Write([]byte(url))
	hSig := fmt.Sprintf("%x", h.Sum(nil))

	if !validateSig(url, hSig) {
		t.Errorf("url hash: %s did not match.", hSig)
	}

	h = hmac.New(sha256.New, []byte("badsecret"))
	h.Write([]byte(url))
	hSig = fmt.Sprintf("%x", h.Sum(nil))

	if validateSig(url, hSig) {
		t.Errorf("bad url hash: %s did not match.", hSig)
	}
}

func TestReq(t *testing.T) {
	h := hmac.New(sha256.New, []byte("secret"))
	h.Write([]byte("http://www.mywot.com/"))
	hSig := fmt.Sprintf("%x", h.Sum(nil))

	rec := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/v1/" + hSig + "/http%3A//www.mywot.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	readReq(rec, req)
	if rec.Code != 200 {
		t.Errorf("Expected %d, returned %d.", 200, rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "http://www.mywot.com/") {
		t.Errorf("http://www.mywot.com/ is not in %s.", rec.Body.String())
	}

	h = hmac.New(sha256.New, []byte("badsecret"))
	h.Write([]byte("http://www.mywot.com/"))
	hSig = fmt.Sprintf("%x", h.Sum(nil))

	rec = httptest.NewRecorder()
	req, err = http.NewRequest("GET", "/v1/" + hSig + "/http%3A//www.mywot.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	readReq(rec, req)
	if rec.Code != 400 {
		t.Errorf("Expected %d, returned %d.", 200, rec.Code)
	}
}
