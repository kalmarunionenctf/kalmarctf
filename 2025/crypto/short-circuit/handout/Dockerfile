FROM node:10-alpine
RUN apk add --no-cache socat

WORKDIR /app
COPY chal.js words.txt flag.txt /app/

CMD ["socat", "tcp4-listen:1337,fork,reuseaddr", "exec:'node chal.js'"]