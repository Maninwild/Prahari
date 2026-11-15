FROM node:22-slim
WORKDIR /app
COPY . ./demo-app
RUN mkdir -p /app/data && chown -R node:node /app
USER node
ENV PRAHARI_DEMO_DATA=/app/data
EXPOSE 3000
CMD ["node","demo-app/server.mjs"]
