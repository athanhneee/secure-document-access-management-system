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

# Install all dependencies with hoisted linker for clean multi-stage copy
RUN pnpm install --frozen-lockfile --config.node-linker=hoisted

# Copy package sources
COPY packages/ ./packages/
COPY apps/api/ ./apps/api/

# Generate Prisma client and compile TypeScript
RUN pnpm --filter @sda/database prisma:generate
RUN pnpm --filter @sda/contracts build
RUN pnpm --filter @sda/security build
RUN pnpm --filter @sda/database build
RUN pnpm --filter @sda/api build

# Prune devDependencies for minimal production bundle
RUN pnpm prune --prod --ignore-scripts --config.node-linker=hoisted

# ── Stage 2: Production Hardened Minimal Runner ──────────────────────────────
FROM node:24.14.1-alpine3.23 AS runner

WORKDIR /app

# Security: Install dumb-init for proper PID 1 signal forwarding and pre-create shared export dir
RUN apk add --no-cache dumb-init wget && \
    addgroup -g 10001 -S appgroup && \
    adduser -u 10001 -S appuser -G appgroup -s /sbin/nologin && \
    mkdir -p /var/lib/sda/exports && \
    chown -R 10001:10001 /var/lib/sda/exports

ENV NODE_ENV=production \
    PORT=3001 \
    HOST=0.0.0.0

# Copy only built artifacts and production dependencies
COPY --from=builder --chown=appuser:appgroup /app/package.json ./package.json
COPY --from=builder --chown=appuser:appgroup /app/node_modules ./node_modules
COPY --from=builder --chown=appuser:appgroup /app/packages/contracts/dist ./packages/contracts/dist
COPY --from=builder --chown=appuser:appgroup /app/packages/contracts/package.json ./packages/contracts/package.json
COPY --from=builder --chown=appuser:appgroup /app/packages/security/dist ./packages/security/dist
COPY --from=builder --chown=appuser:appgroup /app/packages/security/package.json ./packages/security/package.json
COPY --from=builder --chown=appuser:appgroup /app/packages/database/dist ./packages/database/dist
COPY --from=builder --chown=appuser:appgroup /app/packages/database/package.json ./packages/database/package.json
COPY --from=builder --chown=appuser:appgroup /app/apps/api/dist ./apps/api/dist
COPY --from=builder --chown=appuser:appgroup /app/apps/api/package.json ./apps/api/package.json

# Hardening: Run as non-root user
USER 10001:10001

EXPOSE 3001

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:3001/api/v1/health/live || exit 1

ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["node", "apps/api/dist/main.js"]
