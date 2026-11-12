FROM node:24-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends procps ca-certificates && rm -rf /var/lib/apt/lists/*
RUN npm install --global rea-agents@6.9.0 && npm cache clean --force
WORKDIR /app
USER node
ENTRYPOINT ["rea"]
CMD ["--help"]
