# Deployed Teal Brick bridge (opt2). Build context: repository root.
#   docker build -f packages/bridge-server/Dockerfile .
# Public image, no secrets baked in. Runtime env: TB_PORTAL_URL, TB_ENROL_CODE, TB_KEK, TB_PUBLIC_URL,
# TB_DATA_DIR (mount a provider volume at /data; no Dockerfile VOLUME, Railway refuses it), PORT, TB_INTERNAL_PORT,
# optional TB_INTERNAL_HOST (an IP address = private listener address, default `::`, the Railway private network; a NAME = the stable
# host the bridge advertises to its neighbours, not bound), optional TB_OWN_INFRA_ORIGINS (read at boot: a change needs a restart), optional
# TB_PUBLIC_HOST (public listener address; default: no host, i.e. `::` dual stack as before).
# TB_ROLE=views starts the SAME image as the workspace views service (tb-views, LA-1): env TB_VIEWS_UPSTREAM, TB_VIEWS_KEY, PORT;
# no volume, no Portal, no enrolment, no keys; it refuses to start when TB_ENROL_CODE, TB_KEK or TB_PORTAL_URL is set.
# The bridge role takes optional TB_VIEWS_KEY and TB_VIEWS_PUBLIC_URL when the workspace has a views service.
# BSD-04: USER is numeric 1000:1000. Railway runs volume services as root (RAILWAY_RUN_UID=0); the entry then chowns
# TB_DATA_DIR and drops to 1000:1000 (SDK dropPrivileges) before it loads state or listens, and refuses to stay root.
FROM node:24.22.1-bookworm-slim@sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205 AS build
WORKDIR /src
RUN corepack enable
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.json tsconfig.build.json ./
COPY packages ./packages
RUN pnpm install --frozen-lockfile --ignore-scripts \
 && pnpm --filter @opt2-tealbrick/bridge --filter @opt2-tealbrick/bridge-server run build \
 && pnpm --filter @opt2-tealbrick/bridge-server deploy --prod /out

FROM node:24.22.1-bookworm-slim@sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205
ENV NODE_ENV=production TB_DATA_DIR=/data PORT=8080 TB_INTERNAL_PORT=8788
WORKDIR /app
COPY --from=build /out ./
COPY LICENSE NOTICE /app/
LABEL org.opencontainers.image.licenses="LicenseRef-Tealbrick-Proprietary"
RUN mkdir -p /data && chown 1000:1000 /data
USER 1000:1000
EXPOSE 8080 8788
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8080)+'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "dist/server.js"]
