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
COPY --from=build /app/apps/web/dist /usr/share/nginx/html
EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=6 \
    CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1
