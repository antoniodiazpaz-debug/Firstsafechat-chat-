FROM node:22-slim

WORKDIR /usr/src/app

# package.json zuerst kopieren, damit npm install nur bei tatsächlichen
# Abhängigkeitsänderungen neu läuft (Docker-Layer-Caching) — schnellere
# wiederholte Builds, wenn sich nur server.js ändert.
COPY package.json ./
RUN npm install --omit=dev

# Restlichen Projektcode kopieren
COPY . .

ENV NODE_ENV=production
EXPOSE 8787

CMD ["node", "server.js"]
