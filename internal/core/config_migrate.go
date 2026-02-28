package core

import "fmt"

// CurrentConfigVersion is the latest config schema version.
const CurrentConfigVersion = 4

// configMigration defines a single config migration step.
type configMigration struct {
	FromVersion int
	Migrate     func(raw map[string]interface{}) error
}

// configMigrations is the ordered list of all migrations.
// Each migration transforms raw YAML map from FromVersion to FromVersion+1.
var configMigrations = []configMigration{
	{FromVersion: 0, Migrate: migrateV0toV1},
	{FromVersion: 1, Migrate: migrateV1toV2},
	{FromVersion: 2, Migrate: migrateV2toV3},
	{FromVersion: 3, Migrate: migrateV3toV4},
}

// MigrateConfig applies all pending migrations to a raw YAML config map.
// Returns the final version number and whether any migration was applied.
func MigrateConfig(raw map[string]interface{}) (version int, migrated bool, err error) {
	// Extract current version (0 if missing — pre-versioned config).
	switch v := raw["version"].(type) {
	case int:
		version = v
	case float64:
		version = int(v)
	default:
		version = 0
	}

	startVersion := version
	for _, m := range configMigrations {
		if m.FromVersion == version {
			if err := m.Migrate(raw); err != nil {
				return version, version != startVersion,
					fmt.Errorf("migration v%d→v%d failed: %w", m.FromVersion, m.FromVersion+1, err)
			}
			version++
			raw["version"] = version
		}
	}
	return version, version != startVersion, nil
}

// migrateV0toV1 converts dns.tunnel_id (string) → dns.tunnel_ids ([]string).
func migrateV0toV1(raw map[string]interface{}) error {
	dnsRaw, ok := raw["dns"]
	if !ok {
		return nil // no dns section — nothing to migrate
	}
	dns, ok := dnsRaw.(map[string]interface{})
	if !ok {
		return nil
	}

	tunnelID, hasTunnelID := dns["tunnel_id"]
	if !hasTunnelID {
		return nil // already using new format or no tunnel configured
	}

	// Convert single tunnel_id to tunnel_ids list.
	if id, ok := tunnelID.(string); ok && id != "" {
		dns["tunnel_ids"] = []interface{}{id}
	}
	delete(dns, "tunnel_id")
	return nil
}

// migrateV1toV2 assigns sort_index to each tunnel based on its position in the array.
func migrateV1toV2(raw map[string]interface{}) error {
	tunnelsRaw, ok := raw["tunnels"]
	if !ok {
		return nil
	}
	tunnels, ok := tunnelsRaw.([]interface{})
	if !ok {
		return nil
	}

	for i, tRaw := range tunnels {
		t, ok := tRaw.(map[string]interface{})
		if !ok {
			continue
		}
		t["sort_index"] = i
	}
	return nil
}

// migrateV2toV3 adds the dpi_bypass section with defaults (legacy, kept for chain).
func migrateV2toV3(raw map[string]interface{}) error {
	return nil
}

// migrateV3toV4 removes the dpi_bypass section (feature removed).
func migrateV3toV4(raw map[string]interface{}) error {
	delete(raw, "dpi_bypass")
	return nil
}
