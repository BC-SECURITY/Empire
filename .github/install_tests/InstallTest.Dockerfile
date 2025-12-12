# syntax=docker/dockerfile:1.4
ARG BASE_IMAGE
FROM $BASE_IMAGE
WORKDIR /empire
COPY . /empire

SHELL ["/bin/bash", "-c"]

RUN apt-get update && apt-get -y install sudo openssh-client git

# Add a non-root user
RUN echo 'empire ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers
RUN useradd -m empire
RUN chown -R empire:empire /empire
USER empire

RUN sed -i 's/use: mysql/use: sqlite/g' empire/server/config.yaml
RUN ssh-keyscan -H github.com | sudo tee -a /etc/ssh/ssh_known_hosts > /dev/null
# The double install here is intentional.
# It is to check that the install script is idempotent.
# Previously it would fail on a second call to install within the same
# shell due to env variables like GOENV_ROOT not being set yet.
RUN --mount=type=ssh,mode=0666 \
    /empire/setup/install.sh -y && /empire/setup/install.sh -y
RUN rm -rf /empire/empire/server/data/empire*
