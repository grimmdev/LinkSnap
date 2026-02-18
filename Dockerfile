# Stage 1
FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o linksnap .

# Stage 2
FROM alpine:latest

WORKDIR /app

RUN apk --no-cache add ca-certificates

COPY --from=builder /app/linksnap .

RUN mkdir -p data

EXPOSE 3000

ENV PORT=3000
ENV SECRET_KEY=change_this_secret_in_production
ENV SNAPSHOT_API_FORMAT="https://s0.wp.com/mshots/v1/{url}?w=1280&h=720"

VOLUME ["/app/data"]

CMD ["./linksnap"]