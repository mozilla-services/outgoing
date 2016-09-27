package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var urlRe = regexp.MustCompile(`.*?v1/([^/]+)/(.*)`)
var secretKey = flag.String("key", "", "The secret key.")
var debugFlag = flag.Bool("debug", false, "Enable debug logging.")
var addr = flag.String("addr", ":8000", "Where to bind.")
var versionFile = []byte("{}") // global variable to save version info

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

	if url[:10] == "javascript" {
		debug("URL starts with javascript url: %v", url)
		errorResp(w)
		return
	}
	if !strings.Contains(url, "://") {
		url = "http://" + url
	}

	err := redirectTemplate.Execute(
		w,
		&struct {
			Url string
		}{url},
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

func getVersion(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Write(versionFile)
}

func debug(format string, v ...interface{}) {
	if !*debugFlag {
		return
	}
	log.Printf(format, v...)
}

func readReq(w http.ResponseWriter, req *http.Request) {
	switch req.URL.Path {
	case "/":
		home(w)
		return
	case "/__version__":
		getVersion(w)
		return
	case "/__heartbeat__":
		_, err := w.Write([]byte("OK"))
		if err != nil {
			log.Print(err)
		}
		return
	case "/__lbheartbeat__":
		_, err := w.Write([]byte("OK"))
		if err != nil {
			log.Print(err)
		}
		return
	}

	m := urlRe.FindStringSubmatch(req.URL.Path)
	if len(m) < 3 {
		debug("%s didn't match urlRe", req.URL.Path)
		errorResp(w)
		return
	}
	bounce(w, m[1], m[2])
}

func readVersionFile() {

	pwd, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		log.Fatal(err)
	}

	vfiles := [2]string{"/app/version.json", pwd + "/version.json"}
	for _, v := range vfiles {
		versionFile, err = ioutil.ReadFile(v)
		if err != nil {
			log.Print(err)
			continue
		}
		return
	}

	// fail if can't find both version files above
	log.Fatal(errors.New("can't find version.json file"))
	return
}

func main() {
	flag.Parse()

	if *secretKey == "" {
		if os.Getenv("OUTGOING_SECRET_KEY") == "" {
			log.Fatal("-key or OUTGOING_SECRET_KEY (env varible) must be set.")
		}
		*secretKey = os.Getenv("OUTGOING_SECRET_KEY")
	}

	// load the version file once
	readVersionFile()

	http.ListenAndServe(*addr, http.HandlerFunc(readReq))
}
