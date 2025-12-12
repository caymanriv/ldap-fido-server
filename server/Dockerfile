FROM node:22.11.0-alpine

WORKDIR /usr/src/app

COPY package.json package-lock.json ./
RUN npm install --production

COPY . .

ENV NODE_ENV=production

CMD ["node", "src/index.js"]
