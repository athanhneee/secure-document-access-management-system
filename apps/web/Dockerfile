# ── Stage 1: Build Next.js Standalone Output ─────────────────────────────────
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

# Install workspace dependencies with strict lockfile verification
RUN pnpm install --frozen-lockfile

# Copy package and web sources
COPY packages/ ./packages/
COPY apps/web/ ./apps/web/
RUN mkdir -p /app/apps/web/public

# Build contracts and Next.js standalone web bundle (same-origin /api/v1 proxied to internal API service)
ARG NEXT_PUBLIC_API_BASE_URL=/api/v1
ARG INTERNAL_API_ORIGIN=http://api:3001
ENV NEXT_PUBLIC_API_BASE_URL=${NEXT_PUBLIC_API_BASE_URL} \
    INTERNAL_API_ORIGIN=${INTERNAL_API_ORIGIN}
RUN pnpm --filter @sda/contracts build
RUN pnpm --filter @sda/web build

# ── Stage 2: Production Hardened Standalone Runner ───────────────────────────
FROM node:24.14.1-alpine3.23 AS runner

WORKDIR /app

# Upgrade Alpine packages (libcrypto3/libssl3) and strip npm/corepack/yarn from runtime image
RUN apk upgrade --no-cache && \
    apk add --no-cache dumb-init wget && \
    rm -rf /usr/local/lib/node_modules /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack /usr/local/bin/yarn /usr/local/bin/yarnpkg /opt/yarn*

ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0 \
    INTERNAL_API_ORIGIN=http://api:3001

# Copy ONLY Next.js standalone server output, static assets, and public directory
COPY --from=builder --chown=node:node /app/apps/web/.next/standalone ./
COPY --from=builder --chown=node:node /app/apps/web/.next/static ./apps/web/.next/static
COPY --from=builder --chown=node:node /app/apps/web/public ./apps/web/public

USER node

EXPOSE 3000

HEALTHCHECK --interval=15s --timeout=5s --start-period=15s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:3000/ || exit 1

ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["node", "apps/web/server.js"]
