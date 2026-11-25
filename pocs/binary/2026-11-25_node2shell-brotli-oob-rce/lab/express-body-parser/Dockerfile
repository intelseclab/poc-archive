ARG NODE_IMAGE=node@sha256:925de64a85319052d6971ae81ef2417da956e8a3a2c4a0fac732327970f017f5
FROM ${NODE_IMAGE}

LABEL org.opencontainers.image.title="CVE-2026-111497 affected Express body parser lab"
LABEL org.opencontainers.image.version="24.22.0"
LABEL org.opencontainers.image.source="https://github.com/dimasma0305/CVE-2026-111497-POC"

WORKDIR /app
COPY src/package*.json ./
RUN npm install --omit=dev
COPY src/server.js ./
EXPOSE 3000
USER node
CMD ["node", "/app/server.js"]
