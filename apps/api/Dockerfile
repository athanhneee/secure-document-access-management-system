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

# Copy only shared packages and API sources
COPY packages/ ./packages/
COPY apps/api/ ./apps/api/

# Generate Prisma client and compile TypeScript workspace chain
RUN pnpm --filter @sda/database prisma:generate
RUN pnpm --filter @sda/contracts build
RUN pnpm --filter @sda/security build
RUN pnpm --filter @sda/database build
RUN pnpm --filter @sda/api build

# Deploy ONLY @sda/api production runtime dependencies (excluding monorepo dev/web/test packages)
RUN pnpm --filter @sda/api --prod deploy --legacy --ignore-scripts /prod/api && \
    rm -rf /prod/api/dist && cp -R /app/apps/api/dist /prod/api/dist && \
    if [ -d /prod/api/node_modules/@sda/contracts ]; then \
      rm -rf /prod/api/node_modules/@sda/contracts/dist /prod/api/node_modules/@sda/contracts/src /prod/api/node_modules/@sda/contracts/test && \
      cp -R /app/packages/contracts/dist /prod/api/node_modules/@sda/contracts/dist; \
    fi && \
    if [ -d /prod/api/node_modules/@sda/security ]; then \
      rm -rf /prod/api/node_modules/@sda/security/dist /prod/api/node_modules/@sda/security/src /prod/api/node_modules/@sda/security/test && \
      cp -R /app/packages/security/dist /prod/api/node_modules/@sda/security/dist; \
    fi && \
    if [ -d /prod/api/node_modules/@sda/database ]; then \
      rm -rf /prod/api/node_modules/@sda/database/dist /prod/api/node_modules/@sda/database/test /prod/api/node_modules/@sda/database/prisma && \
      cp -R /app/packages/database/dist /prod/api/node_modules/@sda/database/dist && \
      if [ -d /app/packages/database/src/generated ]; then \
        rm -rf /prod/api/node_modules/@sda/database/src && \
        mkdir -p /prod/api/node_modules/@sda/database/src && \
        cp -R /app/packages/database/src/generated /prod/api/node_modules/@sda/database/src/generated; \
      fi; \
    fi && \
    rm -rf /prod/api/src /prod/api/test /prod/api/.turbo /prod/api/Dockerfile /prod/api/tsconfig*

# ── Stage 2: Production Hardened Minimal Runner ──────────────────────────────
FROM node:24.14.1-alpine3.23 AS runner

WORKDIR /app

# Upgrade Alpine packages (libcrypto3/libssl3) and strip npm/corepack/yarn from runtime image
RUN apk upgrade --no-cache && \
    apk add --no-cache dumb-init wget && \
    rm -rf /usr/local/lib/node_modules /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack /usr/local/bin/yarn /usr/local/bin/yarnpkg /opt/yarn* && \
    addgroup -g 10001 -S appgroup && \
    adduser -u 10001 -S appuser -G appgroup -s /sbin/nologin && \
    mkdir -p /var/lib/sda/exports && \
    chown -R 10001:10001 /var/lib/sda/exports

ENV NODE_ENV=production \
    PORT=3001 \
    HOST=0.0.0.0

# Copy ONLY the isolated /prod/api deployment bundle
COPY --from=builder --chown=appuser:appgroup /prod/api ./apps/api

USER 10001:10001

EXPOSE 3001

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:3001/api/v1/health/live || exit 1

ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["node", "apps/api/dist/main.js"]
