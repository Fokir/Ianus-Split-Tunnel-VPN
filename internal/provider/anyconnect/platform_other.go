//go:build !(windows || darwin)

package anyconnect

const (
	fallbackVersion = "5.1.15.287"
	deviceType      = "linux"
	platformVer     = "6.1.0"
)

var (
	agentVer  = fallbackVersion
	userAgent = "AnyConnect Linux " + agentVer
)
