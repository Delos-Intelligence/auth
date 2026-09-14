FROM golang:1.26.8-alpine3.23 as build
ENV GO111MODULE=on
ENV CGO_ENABLED=0
ENV GOOS=linux

RUN apk add --no-cache make git

WORKDIR /go/src/github.com/supabase/auth

# Pulling dependencies
COPY ./Makefile ./go.* ./
COPY ./internal/forks/godotenv ./internal/forks/godotenv
RUN make deps

# Building stuff
COPY . /go/src/github.com/supabase/auth

# Supply the version explicitly when building a Delos release.
ARG RELEASE_VERSION=unspecified
# Only this platform's binary is copied into the image. `make build` also
# cross-compiles three unused binaries (particularly slow under arm64 emulation).
RUN RELEASE_VERSION=${RELEASE_VERSION} make auth

# Always use alpine:3 so the latest version is used. This will keep CA certs more up to date.
FROM alpine:3
RUN adduser -D -u 1000 supabase

RUN apk add --no-cache ca-certificates
COPY --from=build /go/src/github.com/supabase/auth/auth /usr/local/bin/auth
COPY --from=build /go/src/github.com/supabase/auth/migrations /usr/local/etc/auth/migrations/
RUN ln -s /usr/local/bin/auth /usr/local/bin/gotrue

ENV GOTRUE_DB_MIGRATIONS_PATH /usr/local/etc/auth/migrations

USER supabase
CMD ["auth"]
