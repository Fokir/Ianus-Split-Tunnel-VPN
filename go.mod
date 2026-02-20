module awg-split-tunnel

go 1.25.7

require (
	github.com/amnezia-vpn/amneziawg-go v0.0.0-00010101000000-000000000000
	github.com/tailscale/wf v0.0.0-00010101000000-000000000000
	golang.org/x/sys v0.41.0
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/BurntSushi/toml v1.2.1 // indirect
	github.com/google/btree v1.1.3 // indirect
	go4.org/netipx v0.0.0-20220725152314-7e7bdc8411bf // indirect
	golang.org/x/crypto v0.42.0 // indirect
	golang.org/x/exp/typeparams v0.0.0-20221208152030-732eee02a75a // indirect
	golang.org/x/mod v0.28.0 // indirect
	golang.org/x/net v0.44.0 // indirect
	golang.org/x/sync v0.17.0 // indirect
	golang.org/x/time v0.9.0 // indirect
	golang.org/x/tools v0.37.0 // indirect
	golang.org/x/tools/go/expect v0.1.1-deprecated // indirect
	gvisor.dev/gvisor v0.0.0-20231202080848-1f7806d17489 // indirect
	honnef.co/go/tools v0.4.2 // indirect
)

replace github.com/amnezia-vpn/amneziawg-go => ./refs/amneziawg-go

replace github.com/tailscale/wf => ./refs/tailscale-wf
