# FROM --platform=linux/amd64 golang:1.24.3 AS base
FROM --platform=$BUILDPLATFORM golang:1.24.3 AS base

WORKDIR /app/project

COPY ./ ./

FROM base AS builder

RUN go mod download

RUN CGO_ENABLED=0 GOOS=linux go build -o /server ./cmd/app/...

WORKDIR /app

RUN  rm -rf ./project

# FROM --platform=linux/amd64 gcr.io/distroless/base-debian12 AS runtime
FROM --platform=$BUILDPLATFORM gcr.io/distroless/base-debian12 AS runtime

WORKDIR /

COPY --from=builder /server /server

CMD ["/server"]