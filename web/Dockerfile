# Promotional website for SwiftProof: static files served by nginx.
# Build context is the web/ directory, so only public/ and nginx.conf can
# reach the image.
FROM nginx:1.27-alpine-slim

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY public /usr/share/nginx/html

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1/ || exit 1
