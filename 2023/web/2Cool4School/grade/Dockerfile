FROM node

WORKDIR /app
RUN mkdir api
WORKDIR /app/api
COPY api/package.json .
RUN npm install

WORKDIR /app
RUN mkdir frontend
WORKDIR /app/frontend
COPY frontend/package.json .
RUN npm install

WORKDIR /app/api
COPY api .

WORKDIR /app/frontend
COPY frontend .
RUN npm run build
RUN mv build ../api/public

EXPOSE 3000

WORKDIR /app/api
CMD ["node", "app.js"]