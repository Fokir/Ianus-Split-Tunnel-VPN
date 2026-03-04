//go:build !windows

package gateway

// DetectConflictingWFPCallouts is a no-op on non-Windows platforms.
func DetectConflictingWFPCallouts() ([]ConflictingWFPProvider, error) {
	return nil, nil
}

// ConflictingWFPProvider describes a third-party WFP provider that has callout
// rules which may conflict with our TUN routing.
type ConflictingWFPProvider struct {
	Name         string
	Description  string
	CalloutRules int
	TotalRules   int
}
