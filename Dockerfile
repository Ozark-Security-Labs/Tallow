FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o /out/tallow-api ./cmd/tallow-api && go build -o /out/tallow ./cmd/tallow
FROM alpine:3.22
RUN adduser -D -H -u 10001 tallow
COPY --from=build /out/tallow-api /usr/local/bin/tallow-api
COPY --from=build /out/tallow /usr/local/bin/tallow
USER 10001
EXPOSE 8844
ENTRYPOINT ["/usr/local/bin/tallow-api"]
