FROM node:22-alpine AS builder
WORKDIR /app
RUN npm install -g pnpm@9.15.9
COPY package.json pnpm-lock.yaml* ./
RUN pnpm install --frozen-lockfile
COPY . .
RUN pnpm run build 2>/dev/null || pnpm exec tsc -p tsconfig.json 2>/dev/null || true

FROM node:22-alpine AS runner
WORKDIR /app
RUN addgroup --system --gid 1001 rald && adduser --system --uid 1001 rald
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/src ./src
COPY --from=builder /app/package.json ./package.json
USER rald
ENV NODE_ENV=production
ENV PORT=3001
EXPOSE 3001
CMD ["node", "dist/index.js"]
