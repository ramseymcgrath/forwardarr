FROM nginx:latest

COPY nginx.conf /etc/nginx/nginx.conf
RUN mkdir -p /etc/ssl/certs /etc/ssl/private

# Certificates will be provided at runtime; placeholder for permissions
RUN touch /etc/ssl/certs/origin.crt && touch /etc/ssl/private/origin.key
RUN chmod 600 /etc/ssl/private/origin.key

COPY conf.d/ /etc/nginx/conf.d/
