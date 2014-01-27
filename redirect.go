package main

import (
	"html/template"
)
var redirectTemplate *template.Template

func init() {
	redirectTString := `<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <meta http-equiv="refresh" content="0;url={{ .Url }}">
    <title>Redirecting to {{ .Url }}</title>
    <style>
      body {
        margin: 0;
      }
      #main {
        font-family: helvetica;
        text-align: center;
        position: absolute;
        bottom: 1em;
        width: 100%;
        /* Hide the text so people don't see it flash they're going by and
         * getting redirected.  It will be show later with javascript.
         */
        visibility: hidden;
      }
    </style>
    <noscript>
      <style>
      <style>
        #main {
          /* But show the text for the misguided souls without javascript.*/
          visibility: visible;
        }
      </style>
    </noscript>
  </head>
  <body>
    <div id="main">
      <h1>
        Redirecting to <a href="{{ .Url }}">{{ .Url }}</a>
      </h1>
      <strong>
        Please use caution when installing third-party add-ons. If you are
        immediately prompted to install an add-on, please
        <a href="https://addons.mozilla.org/developers/docs/policies/contact">let us know</a>
      </strong>
    </div>
    <script>
      /* Show the text after 2 seconds so people see it if they hit a file
       * download dialog.
       */
      setTimeout(function() {
        var el = document.getElementById('main');
        el.style.visibility = 'visible';
      }, 2000);
    </script>
  </body>
</html>`
	redirectTemplate = template.Must(template.New("redirect").Parse(redirectTString))
}
