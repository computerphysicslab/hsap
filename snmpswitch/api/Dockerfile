# FROM golang:1.13.8 # Do not use this one, because it gives error when using go.mod and git
FROM golang:1.14.7

ENV GOPATH=""

RUN git config --global http.proxy ${HTTP_PROXY}
RUN mkdir -p /usr/local/go/src/apiswitch/
WORKDIR /usr/local/go/src/apiswitch/

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build apiswitch.go

FROM alpine:latest
WORKDIR /root/
COPY --from=0 /usr/local/go/src/apiswitch/apiswitch .
COPY hsapNetwork.yaml /root/
CMD ["./apiswitch", "--viperConfigName=hsapNetwork"] # Exec Form
# CMD ./apiswitch --viperConfigName=hsapNetwork # Shell Form

# Document that the service listens on port 3333
EXPOSE 3333
