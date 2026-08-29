FROM node:22.14-bookworm-slim AS dependencies

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

FROM node:22.14-bookworm-slim AS development

ENV NODE_ENV=development
WORKDIR /app
COPY --from=dependencies /app/node_modules ./node_modules
COPY . .
EXPOSE 3000
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]

FROM dependencies AS build

ARG NEXT_PUBLIC_PLATFORM_API_URL=http://localhost:8000
ENV NEXT_PUBLIC_PLATFORM_API_URL=${NEXT_PUBLIC_PLATFORM_API_URL}
COPY . .
RUN npm run build

FROM node:22.14-bookworm-slim AS production

ENV NODE_ENV=production
WORKDIR /app
COPY --from=build /app ./
EXPOSE 3000
CMD ["npm", "run", "start", "--", "--host", "0.0.0.0"]
