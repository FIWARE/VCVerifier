FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build

ARG TARGETOS
ARG TARGETARCH

WORKDIR /go/src/app
COPY ./ ./

RUN apk add --no-cache build-base

RUN go mod download

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -ldflags="-s -w" -o VCVerifier .

FROM alpine:3.23

LABEL org.opencontainers.image.source="https://github.com/FIWARE/VCVerifier"

WORKDIR /app

COPY --from=build /go/src/app/views ./views
COPY --from=build /go/src/app/VCVerifier ./VCVerifier
COPY --from=build /go/src/app/server.yaml ./server.yaml

CMD ["./VCVerifier"]