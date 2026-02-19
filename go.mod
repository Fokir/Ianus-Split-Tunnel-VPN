module awg-split-tunnel

go 1.25.7

require (
	github.com/amnezia-vpn/amneziawg-go v0.0.0-00010101000000-000000000000
	github.com/google/gopacket v1.1.19
	github.com/wiresock/ndisapi-go v1.0.1
	golang.org/x/sys v0.41.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/google/btree v1.1.3 // indirect
	golang.org/x/crypto v0.42.0 // indirect
	golang.org/x/net v0.44.0 // indirect
	golang.org/x/time v0.9.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	gvisor.dev/gvisor v0.0.0-20231202080848-1f7806d17489 // indirect
)

replace github.com/amnezia-vpn/amneziawg-go => ./refs/amneziawg-go

replace github.com/wiresock/ndisapi-go => ./refs/ndisapi-go
