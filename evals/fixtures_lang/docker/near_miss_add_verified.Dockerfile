# Near miss: ADD fetches a release tarball, and the very next step checks its
# published sha256 before anything is unpacked or run.
FROM alpine:3.20.3

ARG HELM_VERSION=3.16.2
ARG HELM_SHA256=9318379b847e333460d33d291d4c088156299a26cd93d570a7f5d0c36e50b5bb

ADD https://get.helm.sh/helm-v${HELM_VERSION}-linux-amd64.tar.gz /tmp/helm.tar.gz
RUN echo "${HELM_SHA256}  /tmp/helm.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/helm.tar.gz -C /tmp \
    && mv /tmp/linux-amd64/helm /usr/local/bin/helm \
    && rm -rf /tmp/helm.tar.gz /tmp/linux-amd64

RUN adduser -D -u 10001 deploy
USER deploy
ENTRYPOINT ["helm"]
