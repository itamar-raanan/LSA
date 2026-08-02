FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
COPY apps/web/package.json ./apps/web/package.json
RUN npm ci
COPY apps/web ./apps/web

ARG VITE_API_URL=/api/v1
ENV VITE_API_URL=${VITE_API_URL}
RUN npm run build

FROM nginxinc/nginx-unprivileged:1.27-alpine
COPY apps/web/nginx.conf /etc/nginx/conf.d/default.conf
COPY --chmod=755 apps/web/tls-reload.sh /docker-entrypoint.d/40-tls-reload.sh
COPY --chmod=755 apps/web/tls-reload-handler.sh /usr/local/bin/lsa-tls-reload
COPY --from=build /app/apps/web/dist /usr/share/nginx/html
EXPOSE 8443

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=6 \
    CMD wget --no-check-certificate -q -O /dev/null https://127.0.0.1:8443/healthz || exit 1
