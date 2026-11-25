ARG BUILD_FROM
FROM ${BUILD_FROM}

RUN apk add --no-cache ca-certificates

# Binaires statiques (musl) produits par ../scripts/build-addon.sh
ARG BUILD_ARCH
COPY bin/atom-${BUILD_ARCH} /usr/local/bin/atom
COPY run.sh /run.sh
RUN chmod +x /usr/local/bin/atom /run.sh

CMD ["/run.sh"]
