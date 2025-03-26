FROM golang:1.24

COPY version.json /app/version.json
COPY . /go/src/github.com/mozilla-services/outgoing
RUN go install github.com/mozilla-services/outgoing

EXPOSE 8000

CMD ["outgoing"]
