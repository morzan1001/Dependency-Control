# Build stage
FROM node:25-alpine AS builder

# Enable pnpm
RUN npm install -g pnpm

WORKDIR /app

COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile

COPY . .
RUN pnpm build

# Production stage
FROM nginx:alpine-slim

# Install curl for healthcheck
RUN apk add --no-cache curl

COPY --from=builder /app/dist /usr/share/nginx/html

# Copy default nginx.conf (can be overridden by ConfigMap mount)
COPY nginx.conf /etc/nginx/conf.d/default.conf

COPY env.sh /docker-entrypoint.d/40-env-config.sh
RUN chmod +x /docker-entrypoint.d/40-env-config.sh

# Fix permissions for non-root user
RUN chown -R 101:101 /usr/share/nginx/html && \
    chown -R 101:101 /var/cache/nginx && \
    chown -R 101:101 /var/log/nginx && \
    chown -R 101:101 /etc/nginx/conf.d && \
    touch /var/run/nginx.pid && \
    chown 101:101 /var/run/nginx.pid

# Switch to non-root user
USER 101

# Expose both ports (only one will be used at runtime based on TLS config)
EXPOSE 80 443

CMD ["nginx", "-g", "daemon off;"]
