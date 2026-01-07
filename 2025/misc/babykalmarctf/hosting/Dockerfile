FROM python:3.11-slim-bookworm AS build

WORKDIR /opt/CTFd

# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        libffi-dev \
        libssl-dev \
        git \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && python -m venv /opt/venv

ENV PATH="/opt/venv/bin:$PATH"

# Pull CTFd
RUN git clone https://github.com/CTFd/CTFd.git . \
    && git checkout 3.7.6

# Copy the CTFd folder into the container
COPY CTFd CTFd

RUN pip install --no-cache-dir -r requirements.txt \
    && for d in CTFd/plugins/*; do \
        if [ -f "$d/requirements.txt" ]; then \
            pip install --no-cache-dir -r "$d/requirements.txt";\
        fi; \
    done;


FROM python:3.11-slim-bookworm AS release
WORKDIR /opt/CTFd

# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libffi8 \
        libssl3 \
        git \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Pull CTFd
RUN git clone https://github.com/CTFd/CTFd.git . \
    && git checkout 3.7.6

# Copy the CTFd folder into the container
COPY --chown=1001:1001 CTFd CTFd

# Copy the data folder into the container
COPY --chown=1001:1001 .data/CTFd /var/CTFd

RUN useradd \
    --no-log-init \
    --shell /bin/bash \
    -u 1001 \
    ctfd \
    && mkdir -p /var/log/CTFd /var/CTFd/uploads \
    && chown -R 1001:1001 /var/log/CTFd /var/CTFd /opt/CTFd \
    && chmod +x /opt/CTFd/docker-entrypoint.sh

COPY --chown=1001:1001 --from=build /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

ENV UPLOAD_FOLDER=/var/CTFd/uploads
ENV DATABASE_URL=sqlite:////var/CTFd/ctfd.db
ENV FLAG=kalmar{test_flag}

USER 1001
EXPOSE 8000
ENTRYPOINT ["/opt/CTFd/docker-entrypoint.sh"]
