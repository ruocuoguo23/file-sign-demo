FROM golang:1.23 AS builder
WORKDIR /app
COPY . .
RUN go build -o hello

FROM alpine:latest
WORKDIR /root/
COPY --from=builder /app/hello .
CMD ["./hello"]