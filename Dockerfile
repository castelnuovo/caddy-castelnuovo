FROM caddy:2.11.7-builder@sha256:c4cd20eaa0b69112fd5d4f721ffc9671687e1d5d0b155c8620cf7546dbef94c0 AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . ./
RUN go vet ./... && go test ./...
RUN xcaddy build --output /caddy --with github.com/castelnuovo/caddy-castelnuovo=/src

FROM caddy:2.11.7@sha256:36c24ad91a7ff7bc4c87fe22bfa8df3c4b18da0773d73fc12ee2c52b98c0bb7e

LABEL org.opencontainers.image.source="https://github.com/castelnuovo/caddy-castelnuovo" \
      org.opencontainers.image.documentation="https://github.com/castelnuovo/caddy-castelnuovo#readme" \
      org.opencontainers.image.vendor="Castelnuovo Solutions"

COPY --from=build /caddy /usr/bin/caddy
