FROM node:20-alpine
WORKDIR /app

RUN apk add --no-cache openssl python3 make g++

COPY package.json ./
RUN npm install

COPY . .
RUN ./node_modules/.bin/prisma generate
RUN ./node_modules/.bin/nest build

EXPOSE 3002
CMD ./node_modules/.bin/prisma migrate deploy && node dist/main.js