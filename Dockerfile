# Dockerfile used as GitHub action
FROM python:latest AS base

RUN apt-get update --allow-releaseinfo-change && \
    DEBIAN_FRONTEND="noninteractive" apt-get -yq install \
        bash \
        curl \
        jq \
    && t="/tmp/gh-$$.deb" && curl -sSLo "$t" "https://github.com$(curl -sSL "https://github.com/cli/cli/releases/latest" | grep -Po "(?<=href=\")/cli/cli/releases/download/[^\"]*$(dpkg --print-architecture)[.]deb(?=\")")" && apt-get install -y "$t" && rm "$t" \
    rm -rf /var/lib/apt/lists/* $HOME/.python_history $HOME/.wget-hsts

ENV PYTHONPATH="/"

COPY entrypoint.sh /entrypoint.sh
COPY trivy_report /trivy_report

RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
