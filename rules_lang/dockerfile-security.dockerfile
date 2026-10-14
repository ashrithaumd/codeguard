# ruleid: codeguard-dockerfile-latest-tag
FROM node:latest AS deps
# ok: codeguard-dockerfile-latest-tag
FROM python:3.12-slim AS builder
# ok: codeguard-dockerfile-latest-tag
FROM builder AS tested

# ruleid: codeguard-dockerfile-curl-pipe-shell
RUN curl -fsSL https://get.example.com/install.sh | sh
# ruleid: codeguard-dockerfile-curl-pipe-shell
RUN wget -qO- https://example.com/setup | sudo bash -
# ok: codeguard-dockerfile-curl-pipe-shell
RUN curl -fsSLo /tmp/install.sh https://get.example.com/install.sh && sha256sum -c /tmp/install.sha256

# ruleid: codeguard-dockerfile-add-remote-url
ADD https://example.com/tool.tar.gz /opt/
# ok: codeguard-dockerfile-add-remote-url
ADD --checksum=sha256:24454f830cdb571e2c4ad15481119c43b3cafd48dd869a9b2945d1036d1dc68d https://example.com/tool.tar.gz /opt/
# ok: codeguard-dockerfile-add-remote-url
ADD vendor.tar.gz /opt/

# ruleid: codeguard-dockerfile-insecure-download
RUN curl -k https://internal.example.com/cert.pem -o /etc/cert.pem
# ruleid: codeguard-dockerfile-insecure-download
RUN wget --no-check-certificate https://example.com/a.tgz
# ruleid: codeguard-dockerfile-insecure-download
RUN apt-get install -y --allow-unauthenticated mypkg
# ruleid: codeguard-dockerfile-insecure-download
RUN pip install --trusted-host pypi.example.com mypkg
# ok: codeguard-dockerfile-insecure-download
RUN curl -fsSL https://example.com/a.tgz -o /tmp/a.tgz

# ruleid: codeguard-dockerfile-secret-in-env
ENV DB_PASSWORD=hunter22
# ruleid: codeguard-dockerfile-secret-in-env
ARG API_TOKEN=abc123def456
# ok: codeguard-dockerfile-secret-in-env
ENV PASSWORD_FILE=/run/secrets/db_password
# ok: codeguard-dockerfile-secret-in-env
ENV NODE_ENV=production

# ruleid: codeguard-dockerfile-secret-build-arg
ARG GITHUB_TOKEN
# ok: codeguard-dockerfile-secret-build-arg
ARG APP_VERSION

# ruleid: codeguard-dockerfile-world-writable
RUN chmod -R 777 /app
# ok: codeguard-dockerfile-world-writable
RUN chmod 755 /app/entrypoint.sh

# ruleid: codeguard-dockerfile-private-key-copied
COPY id_rsa /root/.ssh/id_rsa
# ok: codeguard-dockerfile-private-key-copied
COPY id_rsa.pub /root/.ssh/authorized_keys

# ok: codeguard-dockerfile-user-root
USER root
RUN apt-get update && apt-get install -y --no-install-recommends tini
USER app

# ruleid: codeguard-dockerfile-user-root
USER root
CMD ["node", "server.js"]
