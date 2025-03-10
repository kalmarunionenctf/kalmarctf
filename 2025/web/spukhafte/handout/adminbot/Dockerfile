FROM fedora:latest

# RUN apt-get update && apt-get install -y \
#     chromium \
#     chromium-sandbox \
#     --no-install-recommends \
#     && rm -rf /var/lib/apt/lists/*
RUN dnf update -y && dnf install -y chromium nodejs

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY adminbot.js .

ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium-browser

RUN useradd -m user
USER user
CMD ["node", "adminbot.js"]
