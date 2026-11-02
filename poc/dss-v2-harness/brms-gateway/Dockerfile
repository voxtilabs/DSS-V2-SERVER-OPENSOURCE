FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY src/ ./src/

# E-028: the REAL production DSS web bundle mirrored to web-module/ (gitignored;
# mirrored by a lab script, shipped inside the image only).
COPY web-module/ ./web-module/

EXPOSE 1443 11443

CMD ["node", "src/index.js"]