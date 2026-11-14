# ── Stage 1: Build & Isolated Production Deploy ──────────────────────────────
FROM node:24.14.1-alpine3.23 AS builder

WORKDIR /app

ENV CI=true \
    HUSKY=0

RUN apk add --no-cache libc6-compat
RUN npm install -g pnpm@12.4.1 --no-fund --no-audit

# Copy workspace configuration, preinstall check, and all workspace manifests
COPY .npmrc pnpm-lock.yaml pnpm-workspace.yaml package.json turbo.json ./
COPY scripts/check-toolchain.mjs ./scripts/check-toolchain.mjs
COPY packages/config/package.json ./packages/config/
COPY packages/contracts/package.json ./packages/contracts/
COPY packages/database/package.json ./packages/database/
COPY packages/security/package.json ./packages/security/
COPY packages/testing/package.json ./packages/testing/
COPY apps/api/package.json ./apps/api/
COPY apps/web/package.json ./apps/web/
COPY apps/worker/package.json ./apps/worker/

# Install workspace dependencies with strict lockfile verification
RUN pnpm install --frozen-lockfile

# Copy only shared packages and worker sources
COPY packages/ ./packages/
COPY apps/worker/ ./apps/worker/

# Generate Prisma client and compile TypeScript workspace chain
RUN pnpm --filter @sda/database prisma:generate
RUN pnpm --filter @sda/contracts build
RUN pnpm --filter @sda/security build
RUN pnpm --filter @sda/database build
RUN pnpm --filter @sda/worker build

# Deploy ONLY @sda/worker production runtime dependencies (excluding monorepo dev/web/api packages)
RUN pnpm --filter @sda/worker --prod deploy --legacy --ignore-scripts /prod/worker && \
    rm -rf /prod/worker/dist && cp -R /app/apps/worker/dist /prod/worker/dist && \
    if [ -d /prod/worker/node_modules/@sda/contracts ]; then \
      rm -rf /prod/worker/node_modules/@sda/contracts/dist /prod/worker/node_modules/@sda/contracts/src /prod/worker/node_modules/@sda/contracts/test && \
      cp -R /app/packages/contracts/dist /prod/worker/node_modules/@sda/contracts/dist; \
    fi && \
    if [ -d /prod/worker/node_modules/@sda/security ]; then \
      rm -rf /prod/worker/node_modules/@sda/security/dist /prod/worker/node_modules/@sda/security/src /prod/worker/node_modules/@sda/security/test && \
      cp -R /app/packages/security/dist /prod/worker/node_modules/@sda/security/dist; \
    fi && \
    if [ -d /prod/worker/node_modules/@sda/database ]; then \
      rm -rf /prod/worker/node_modules/@sda/database/dist /prod/worker/node_modules/@sda/database/test /prod/worker/node_modules/@sda/database/prisma && \
      cp -R /app/packages/database/dist /prod/worker/node_modules/@sda/database/dist && \
      if [ -d /app/packages/database/src/generated ]; then \
        rm -rf /prod/worker/node_modules/@sda/database/src && \
        mkdir -p /prod/worker/node_modules/@sda/database/src && \
        cp -R /app/packages/database/src/generated /prod/worker/node_modules/@sda/database/src/generated; \
      fi; \
    fi && \
    rm -rf /prod/worker/src /prod/worker/test /prod/worker/.turbo /prod/worker/Dockerfile /prod/worker/tsconfig*

# ── Stage 2: Production Hardened Minimal Runner ──────────────────────────────
FROM node:24.14.1-alpine3.23 AS runner

WORKDIR /app

# Upgrade Alpine packages (libcrypto3/libssl3) and strip npm/corepack/yarn from runtime image
RUN apk upgrade --no-cache && \
    apk add --no-cache dumb-init && \
    rm -rf /usr/local/lib/node_modules /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack /usr/local/bin/yarn /usr/local/bin/yarnpkg /opt/yarn* && \
    addgroup -g 10001 -S appgroup && \
    adduser -u 10001 -S appuser -G appgroup -s /sbin/nologin && \
    mkdir -p /var/lib/sda/exports && \
    chown -R 10001:10001 /var/lib/sda/exports

ENV NODE_ENV=production \
    ICAP_BIND_HOST=0.0.0.0 \
    ICAP_PORT=1344 \
    WORKER_HEALTH_HOST=0.0.0.0 \
    WORKER_HEALTH_PORT=9102

# Copy ONLY the isolated /prod/worker deployment bundle
COPY --from=builder --chown=appuser:appgroup /prod/worker ./apps/worker

USER 10001:10001

EXPOSE 1344 9102

HEALTHCHECK --interval=20s --timeout=5s --start-period=15s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:'+(process.env.WORKER_HEALTH_PORT||9102)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]

ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["node", "apps/worker/dist/main.js"]
