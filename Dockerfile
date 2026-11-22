FROM node:24-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY tsconfig.json ./
COPY server ./server
RUN npm run build

FROM node:24-bookworm-slim AS production-deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund && npm cache clean --force

FROM node:24-bookworm-slim AS runtime
ENV NODE_ENV=production PORT=54873 DATA_DIR=/app/data
WORKDIR /app
COPY --from=production-deps --chown=node:node /app/node_modules ./node_modules
COPY --chown=node:node package.json ./
COPY --from=build --chown=node:node /app/dist ./dist
COPY --chown=node:node web ./web
RUN install -d -m 0700 -o node -g node /app/data
USER node
EXPOSE 54873
VOLUME ["/app/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD ["node", "-e", "const s=require('node:net').connect(Number(process.env.PORT||54873),'127.0.0.1');s.setTimeout(3000);s.on('connect',()=>{s.end();process.exit(0)});s.on('error',()=>process.exit(1));s.on('timeout',()=>process.exit(1))"]
CMD ["node", "dist/server/main.js"]
