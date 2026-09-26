# syntax=docker/dockerfile:1
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json tsconfig.build.json ./
COPY scripts ./scripts
COPY src ./src
ARG NOIP_GIT_SHA=unknown
ENV NOIP_GIT_SHA=${NOIP_GIT_SHA}
RUN npm run build

FROM node:22-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY --from=build /app/dist ./dist
COPY fixtures ./fixtures
COPY schemas ./schemas
ARG NOIP_GIT_SHA=unknown
ENV NOIP_GIT_SHA=${NOIP_GIT_SHA}
USER node
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s CMD wget -qO- http://127.0.0.1:${PORT:-3000}/health >/dev/null || exit 1
CMD ["node", "--no-deprecation", "dist/api/server.js"]
