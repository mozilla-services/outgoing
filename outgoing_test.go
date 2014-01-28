package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/hmac"
	"fmt"
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
