# Dockerfile used as GitHub action
FROM python:latest AS base

RUN curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | tee /etc/apt/sources.list.d/github-cli.list > /dev/null && \
    apt-get update --allow-releaseinfo-change && \
    DEBIAN_FRONTEND="noninteractive" apt-get -yq install \
        bash \
        curl \
        jq \
        gh && \
    rm -rf /var/lib/apt/lists/* $HOME/.python_history $HOME/.wget-hsts

ENV PYTHONPATH="/"

COPY entrypoint.sh /entrypoint.sh
COPY trivy_report /trivy_report

RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
