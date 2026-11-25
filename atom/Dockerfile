ARG BUILD_FROM=ghcr.io/home-assistant/amd64-base:3.21

# Compilation du binaire Atom (Alpine, donc musl : binaire statique)
FROM rust:1-alpine AS build
RUN apk add --no-cache build-base
WORKDIR /src
COPY app/Cargo.toml app/Cargo.lock ./
COPY app/src ./src
COPY app/ui ./ui
RUN cargo build --release

# Image finale de l'add-on
FROM ${BUILD_FROM}
RUN apk add --no-cache ca-certificates
COPY --from=build /src/target/release/atom /usr/local/bin/atom
COPY run.sh /run.sh
RUN chmod +x /usr/local/bin/atom /run.sh

CMD ["/run.sh"]
