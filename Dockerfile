# syntax=docker/dockerfile:1.4

# NOTE: Only use this when you want to build image locally
#       else use `docker pull bcsecurity/empire:{VERSION}`
#       all image versions can be found at: https://hub.docker.com/r/bcsecurity/empire/

# -----BUILD COMMANDS----
# 1) build command: `docker build -t bcsecurity/empire .`
# 2) create volume storage: `docker create -v /empire --name data bcsecurity/empire`
# 3) run out container: `docker run -it --volumes-from data bcsecurity/empire /bin/bash`

FROM python:3.14.3-trixie

LABEL maintainer="bc-security"
LABEL description="Dockerfile for Empire. https://bc-security.gitbook.io/empire-wiki/quickstart/installation#docker"

ENV DEBIAN_FRONTEND=noninteractive DOTNET_CLI_TELEMETRY_OPTOUT=1

ARG TARGETARCH
ARG COMMIT_SHA=""
ENV EMPIRE_COMMIT_SHA=$COMMIT_SHA

SHELL ["/bin/bash", "-c"]

RUN apt-get update && \
    apt-get install -qq \
    --no-install-recommends \
    apt-transport-https \
    ca-certificates \
    libicu-dev \
    sudo \
    zip \
    curl \
    wget \
    git \
    openssh-client \
    default-jdk \
    mono-runtime \
    build-essential \
    mingw-w64 \
    perl \
    && rm -rf /var/lib/apt/lists/*

RUN if [ "$TARGETARCH" = "amd64" ]; then \
        PS_ARCH="x64"; \
    elif [ "$TARGETARCH" = "arm64" ]; then \
        PS_ARCH="arm64"; \
    fi && \
    curl -L -o /tmp/powershell.tar.gz https://github.com/PowerShell/PowerShell/releases/download/v7.3.9/powershell-7.3.9-linux-${PS_ARCH}.tar.gz && \
    mkdir -p /opt/microsoft/powershell/7 && \
    tar zxf /tmp/powershell.tar.gz -C /opt/microsoft/powershell/7 && \
    chmod +x /opt/microsoft/powershell/7/pwsh && \
    ln -s /opt/microsoft/powershell/7/pwsh /usr/bin/pwsh && \
    rm /tmp/powershell.tar.gz

RUN curl -sSL https://install.python-poetry.org | python3 - && \
    ln -s /root/.local/bin/poetry /usr/bin

ENV PARENT_PATH="/empire"

RUN curl -L -o /tmp/go.tar.gz https://go.dev/dl/go1.23.2.linux-${TARGETARCH}.tar.gz && \
    tar zxf /tmp/go.tar.gz -C /opt && \
    ln -s /opt/go/bin/go /usr/bin/go && \
    rm /tmp/go.tar.gz

# Build OpenSSL for MinGW cross-compilation (for Windows C stagers)
RUN set -eux; \
    if [ ! -d /opt/openssl-mingw64/include/openssl ]; then \
      OPENSSL_VERSION="3.5.4"; \
      mkdir -p /tmp/openssl-build; \
      cd /tmp/openssl-build; \
      wget -q "https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz" -O "openssl-${OPENSSL_VERSION}.tar.gz"; \
      tar -xzf "openssl-${OPENSSL_VERSION}.tar.gz"; \
      cd "openssl-${OPENSSL_VERSION}"; \
      ./Configure mingw64 no-apps no-async no-docs no-shared no-tests \
        --cross-compile-prefix=x86_64-w64-mingw32- \
        --prefix=/opt/openssl-mingw64; \
      make -j"$(nproc)"; \
      make install_dev; \
      cd /; \
      rm -rf /tmp/openssl-build; \
    fi

WORKDIR /empire

COPY pyproject.toml poetry.lock /empire/

RUN poetry config virtualenvs.create false && \
    poetry install --no-root

COPY . /empire

RUN rm -rf /empire/empire/server/data/empire*

RUN sed -i 's/use: mysql/use: sqlite/g' empire/server/config.yaml

RUN --mount=type=ssh,id=default,mode=0666 \
    ssh-keyscan -H github.com > /tmp/known_hosts && \
    export GIT_SSH_COMMAND='ssh -o UserKnownHostsFile=/tmp/known_hosts -o StrictHostKeyChecking=yes' && \
    ./ps-empire -f setup

ENTRYPOINT ["./ps-empire"]
CMD ["-f", "server"]
