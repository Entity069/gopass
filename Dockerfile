FROM golang:1.27.1-bookworm AS source
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .

FROM source AS test
RUN go vet ./... && go test -race -count=1 ./...

FROM source AS build
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/cli-login ./cmd/login
RUN mkdir -p /rootfs/data && chmod 0700 /rootfs/data && chown 10001:10001 /rootfs/data

FROM scratch AS runtime
COPY --from=build /out/cli-login /cli-login

COPY --from=build /rootfs/ /
USER 10001:10001
WORKDIR /data
ENV APP_DATA_DIR=/data
ENTRYPOINT ["/cli-login"]
