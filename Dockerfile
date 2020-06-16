FROM golang:1.14 AS builder

RUN apt-get -qq update && apt-get -yqq install upx

ENV GO111MODULE=on \
  CGO_ENABLED=0 \
  GOOS=linux \
  GOARCH=amd64

WORKDIR /src

COPY . .
RUN go build \
  -a \
  -trimpath \
  -ldflags "-s -w -extldflags '-static'" \
  -installsuffix cgo \
  -tags netgo \
  -mod vendor \
  -o /bin/vault-setup-github \
  .

RUN strip /bin/vault-setup-github

RUN upx -q -9 /bin/vault-setup-github




FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /bin/vault-setup-github /bin/vault-setup-github
CMD ["/bin/vault-setup-github"]
