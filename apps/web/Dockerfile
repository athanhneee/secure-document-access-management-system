# ── Stage 1: Build & Dependencies ─────────────────────────────────────────────
FROM node:24.14.1-alpine3.23 AS builder

WORKDIR /app

ENV CI=true \
    HUSKY=0 \
    NEXT_TELEMETRY_DISABLED=1

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
COPY apps/web/ ./apps/web/

# Build contracts and Next.js web application
ARG NEXT_PUBLIC_API_BASE_URL=/api/v1
ENV NEXT_PUBLIC_API_BASE_URL=${NEXT_PUBLIC_API_BASE_URL}
RUN pnpm --filter @sda/contracts build
RUN pnpm --filter @sda/web build

# Prune devDependencies before copying into runner image
RUN pnpm prune --prod --ignore-scripts --config.node-linker=hoisted

# ── Stage 2: Production Hardened Minimal Runner ──────────────────────────────
FROM node:24.14.1-alpine3.23 AS runner

WORKDIR /app

RUN apk add --no-cache dumb-init wget

ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0

COPY --from=builder --chown=node:node /app/package.json ./package.json
COPY --from=builder --chown=node:node /app/node_modules ./node_modules
COPY --from=builder --chown=node:node /app/packages/contracts/dist ./packages/contracts/dist
COPY --from=builder --chown=node:node /app/packages/contracts/package.json ./packages/contracts/package.json
COPY --from=builder --chown=node:node /app/apps/web/public ./apps/web/public
COPY --from=builder --chown=node:node /app/apps/web/.next ./apps/web/.next
COPY --from=builder --chown=node:node /app/apps/web/next.config.ts ./apps/web/next.config.ts
COPY --from=builder --chown=node:node /app/apps/web/package.json ./apps/web/package.json

USER node

EXPOSE 3000

HEALTHCHECK --interval=15s --timeout=5s --start-period=15s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:3000/ || exit 1

ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["node", "node_modules/next/dist/bin/next", "start", "apps/web"]
