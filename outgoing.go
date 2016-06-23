package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"flag"
	"fmt"
	"html"
	"log"
	"net/http"
	"regexp"
	"strings"
)

var urlRe = regexp.MustCompile(`.*?v1/([^/]+)/(.*)`)
var secretKey = flag.String("key", "", "The secret key.")
var debugFlag = flag.Bool("debug", false, "Enable debug logging.")
var addr = flag.String("addr", ":8000", "Where to bind.")

func sha1Str(msg string) string {
	h := sha1.New()
	h.Write([]byte(msg))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func sha256Mac(msg, key string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(msg))
	return fmt.Sprintf("%x", mac.Sum(nil))
}

func errorResp(w http.ResponseWriter) {
	w.WriteHeader(http.StatusBadRequest)
	w.Write([]byte("Invalid address."))
}

func validateSig(url, sig string) bool {
	if sha1Str(*secretKey+url) == sig || sha256Mac(url, *secretKey) == sig {
		return true
	}
	return false
}

func bounce(w http.ResponseWriter, sig, url string) {
	if !validateSig(url, sig) {
		debug("Could not validate sig, url: %v, sig: %v", url, sig)
		errorResp(w)
		return
	}

	safeUrl := html.EscapeString(url)
	if safeUrl[:10] == "javascript" {
		debug("URL starts with javascript url: %v", url)
		errorResp(w)
		return
	}
	if !strings.Contains(safeUrl, "://") {
		safeUrl = "http://" + safeUrl
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

func debug(format string, v ...interface{}) {
	if !*debugFlag {
		return
	}
	log.Printf(format, v...)
}

func readReq(w http.ResponseWriter, req *http.Request) {
	if req.URL.RequestURI() == "/" {
		home(w)
		return
	}

	m := urlRe.FindStringSubmatch(req.URL.RequestURI())
	if len(m) < 3 {
		debug("%s didn't match urlRe", req.URL.RequestURI())
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
