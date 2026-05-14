# v-sdk-go

Go SDK for the Vector Network.

This repository is a self-contained client layer for:
- services
- node tools
- microservices
- network utilities

It follows the SDK contract shape described in the Vector Network docs:
- canonical `OperationRequest` / `OperationResponse` / `OperationError`
- client-side validation
- deterministic serialization
- signed requests
- clear separation between client state and authoritative kernel state

## Included

- wallet creation and binding
- request signing
- canonical JSON serialization
- HTTP transport
- typed operation helpers
- query and record helpers
- protocol metadata helpers
- mock transport for tests and local development
- CLI entrypoint

## Build

```bash
go build ./...
```

## Test

```bash
go test ./...
```

## CLI

```bash
go run ./cmd/v-sdk-go --help
```

## Default node endpoints

- `POST /v1/operations`
- `POST /v1/query`
- `POST /v1/records`
- `GET  /v1/protocol`
- `GET  /v1/events/stream`

These routes are configurable in `Config`.
