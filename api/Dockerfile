FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod ./
COPY main.go ./
RUN go mod tidy
RUN go build -o radius-api .

FROM alpine:latest
# Install Docker CLI so the API can orchestrate the radius container
RUN apk update && apk add --no-cache docker-cli

WORKDIR /app
COPY --from=builder /app/radius-api .
COPY index.html .

EXPOSE 8000
CMD ["./radius-api"]
