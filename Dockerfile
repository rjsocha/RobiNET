# The connector: what runs inside the network being exposed.
#
# No capabilities and no /dev/net/tun. Everything happens in a user space
# network stack, which is the whole reason this image works on a platform that
# hands out a container and nothing else.

FROM golang:1.26-alpine AS build

ARG VERSION=dev

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X github.com/rjsocha/robinet/internal/version.Build=${VERSION}" \
      -o /out/robinet ./cmd/robinet

FROM alpine

# ca-certificates so a hub with a real certificate can be verified, and enough
# to look around from inside the network being exposed, which is the first
# thing anybody wants when a connector is not carrying what they expect.
RUN apk add --no-cache ca-certificates bind-tools curl

# On PATH, so docker exec into a running container finds it: the command line
# and the daemon are the same binary, and reaching one inside a container is
# how it is driven there.
COPY --from=build /out/robinet /usr/local/bin/robinet

# The state directory holds the connector's keypair, which is its identity.
# Mount it: without a volume every restart comes back as a stranger and has to
# be approved again.
ENV ROBINET_STATE=/data
VOLUME /data

ENTRYPOINT ["/usr/local/bin/robinet"]
CMD ["connect"]
