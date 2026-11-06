# ── Stage 1: Build & Dependencies ─────────────────────────────────────────────
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

# Install dependencies with hoisted linker for clean multi-stage copy
RUN pnpm install --frozen-lockfile --config.node-linker=hoisted

# Copy package sources
COPY packages/ ./packages/
COPY apps/worker/ ./apps/worker/

# Generate Prisma client and compile TypeScript
RUN pnpm --filter @sda/database prisma:generate
RUN pnpm --filter @sda/contracts build
RUN pnpm --filter @sda/security build
RUN pnpm --filter @sda/database build
RUN pnpm --filter @sda/worker build

# Prune devDependencies for minimal production bundle
RUN pnpm prune --prod --ignore-scripts --config.node-linker=hoisted && \
    rm -rf /app/node_modules/@typescript /app/node_modules/typescript

# ── Stage 2: Production Hardened Minimal Runner ──────────────────────────────
FROM node:24.14.1-alpine3.23 AS runner

WORKDIR /app

# CONFLICT-RESOLVED: Nâng cấp gói hệ thống Alpine (vá CVE-2026-14456/CVE-2026-45447 trên libcrypto3/libssl3) và gỡ bỏ npm/corepack/yarn khỏi ảnh runtime để loại bỏ CVE-2026-59873 của node-tar khi quét Trivy CD.
RUN apk upgrade --no-cache && \
    apk add --no-cache dumb-init && \
    rm -rf /usr/local/lib/node_modules /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack /usr/local/bin/yarn /usr/local/bin/yarnpkg /opt/yarn* && \
    addgroup -g 10001 -S appgroup && \
    adduser -u 10001 -S appuser -G appgroup -s /sbin/nologin && \
    mkdir -p /var/lib/sda/exports && \
    chown -R 10001:10001 /var/lib/sda/exports

ENV NODE_ENV=production

COPY --from=builder --chown=appuser:appgroup /app/package.json ./package.json
COPY --from=builder --chown=appuser:appgroup /app/node_modules ./node_modules
COPY --from=builder --chown=appuser:appgroup /app/packages/contracts/dist ./packages/contracts/dist
COPY --from=builder --chown=appuser:appgroup /app/packages/contracts/package.json ./packages/contracts/package.json
COPY --from=builder --chown=appuser:appgroup /app/packages/security/dist ./packages/security/dist
COPY --from=builder --chown=appuser:appgroup /app/packages/security/package.json ./packages/security/package.json
COPY --from=builder --chown=appuser:appgroup /app/packages/database/dist ./packages/database/dist
COPY --from=builder --chown=appuser:appgroup /app/packages/database/package.json ./packages/database/package.json
COPY --from=builder --chown=appuser:appgroup /app/apps/worker/dist ./apps/worker/dist
COPY --from=builder --chown=appuser:appgroup /app/apps/worker/package.json ./apps/worker/package.json

USER 10001:10001

EXPOSE 1344

ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["node", "apps/worker/dist/main.js"]
