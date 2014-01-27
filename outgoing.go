package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/hmac"
	"fmt"
	"log"
	"flag"
	"io"
	"html"
	"net/http"
	"regexp"
)

var urlRe *regexp.Regexp
var secretKey = flag.String("key", "", "The secret key.")
var addr = flag.String("addr", ":9090", "Where to bind.")

func init() {
	urlRe = regexp.MustCompile(`.*?v1/([^/]+)/(.*)`)
}

func sha1Str(msg string) string {
	h := sha1.New()
	io.WriteString(h, msg)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func sha256Mac(msg, key string) string {
	mac := hmac.New(sha256.New, []byte(key))
	io.WriteString(mac, msg)
	return fmt.Sprintf("%x", mac.Sum(nil))
}

func errorResp(w http.ResponseWriter) {
	w.WriteHeader(http.StatusBadRequest)
	w.Write([]byte("Invalid address."))
}

func validateSig(url, sig string) bool {
	if sha1Str(*secretKey + url) == sig || sha256Mac(url, *secretKey) == sig {
		return true
	}
	return false
}

func bounce(w http.ResponseWriter, sig, url string) {
	if !validateSig(url, sig) {
		errorResp(w)
		return
	}

	safeUrl := html.EscapeString(url)
	if safeUrl[:10] == "javascript" {
		errorResp(w)
		return
	}
	err := redirectTemplate.Execute(
		w,
		&struct {
			Url string
		}{safeUrl},
	)
	if err != nil {
		log.Println(err)
	}
}

func home(w http.ResponseWriter) {
	homeHtml := `<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title>outgoing urls</title>
  </head>
  <body>
    <h1>outgoing urls.</h1>
  </body>
</html>`
	w.Write([]byte(homeHtml))

}

func readReq(w http.ResponseWriter, req *http.Request) {
	if req.URL.RequestURI() == "/" {
		home(w)
		return
	}

	m := urlRe.FindStringSubmatch(req.URL.RequestURI())
	if len(m) < 3 {
		errorResp(w)
		return
	}
	bounce(w, m[1], m[2])
}

func main() {
	flag.Parse()
	if *secretKey == "" {
		log.Fatal("-key must be set.")
	}
	http.ListenAndServe(*addr, http.HandlerFunc(readReq))
}
