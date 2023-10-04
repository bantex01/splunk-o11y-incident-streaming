FROM golang:alpine AS builder

RUN apk update && apk add --no-cache git

WORKDIR $GOPATH/src/splunk-o11y-incident-streaming/
COPY . .

RUN go get -d -v
RUN go build -o /go/bin/splunk_o11y_sas

RUN mkdir /config
RUN chmod 777 /config

# Stage 2: Create the final image with a shell
FROM busybox

# Copy the Go binary from the builder stage
COPY --from=builder /go/bin/splunk_o11y_sas /go/bin/splunk_o11y_sas
COPY --from=builder /etc/ssl/certs /etc/ssl/certs

# Copy a minimal shell binary from BusyBox
COPY --from=busybox /bin/sh /bin/sh

# Make the shell executable
RUN chmod +x /bin/sh

# Set the ENTRYPOINT to your Go application
ENTRYPOINT ["/go/bin/splunk_o11y_sas"]