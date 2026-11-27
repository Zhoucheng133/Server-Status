FROM --platform=$BUILDPLATFORM oven/bun:1.4.4 AS frontend
WORKDIR /src/frontend
COPY frontend/package.json frontend/bun.lock ./
RUN bun install --frozen-lockfile
COPY frontend/ ./
RUN bun run --bun build

FROM --platform=$BUILDPLATFORM golang:1.26 AS backend
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
COPY geo/ ./geo/
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -o /out/server-status .

FROM alpine:3.23
WORKDIR /app
RUN mkdir -p db caddy_log && chown 65532:65532 db
COPY --from=backend /out/server-status /app/server-status
COPY --from=backend /src/geo/NOTICE.md /app/geo/NOTICE.md
COPY --from=frontend /src/frontend/dist/ /app/frontend/dist/
USER 65532:65532
EXPOSE 3000
ENTRYPOINT ["/app/server-status"]
