//go:build ignore

package api

//go:generate protoc --proto_path=proto --go_out=gen --go_opt=paths=source_relative --go-grpc_out=gen --go-grpc_opt=paths=source_relative proto/vpn_service.proto
