FROM golang:alpine AS builder

RUN apk update && apk add --no-cache git

WORKDIR $GOPATH/src/splunk-o11y-incident-streaming/
COPY . .

RUN go get -d -v
RUN go build -o /go/bin/splunk_o11y_sas

RUN mkdir /config
RUN chmod 777 /config


#######################################################

FROM scratch
COPY --from=builder /go/bin/splunk_o11y_sas /go/bin/splunk_o11y_sas

#RUN mkdir /config
#RUN chmod 777 /config

ENTRYPOINT ["/go/bin/splunk_o11y_sas"]



