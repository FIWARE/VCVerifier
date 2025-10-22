FROM golang:1.24-alpine AS build

WORKDIR /go/src/app
COPY ./ ./

RUN apk add build-base

RUN go get -d -v ./...
RUN go build -v .

FROM golang:1.24-alpine

LABEL org.opencontainers.image.source="https://github.com/FIWARE/VCVerifier"

WORKDIR /go/src/app

COPY --from=build /go/src/app/views /go/src/app/views
COPY --from=build /go/src/app/VCVerifier /go/src/app/VCVerifier
COPY --from=build /go/src/app/server.yaml /go/src/app/server.yaml

CMD ["./VCVerifier"]