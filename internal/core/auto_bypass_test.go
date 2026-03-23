package core

import "testing"

func TestAutoBypass_ShouldBypass_SteamGame(t *testing.T) {
	ab := NewAutoBypass(AutoBypassConfig{Enabled: true})
	if !ab.ShouldBypass(`e:\steamlibrary\steamapps\common\marvelrivals\marvel-win64-shipping.exe`, "marvel-win64-shipping.exe") {
		t.Fatal("expected bypass for Steam game")
	}
}

func TestAutoBypass_ShouldBypass_EpicGame(t *testing.T) {
	ab := NewAutoBypass(AutoBypassConfig{Enabled: true})
	if !ab.ShouldBypass(`c:\program files\epic games\fortnite\fortniteclient-win64-shipping.exe`, "fortniteclient-win64-shipping.exe") {
		t.Fatal("expected bypass for Epic game")
	}
}

func TestAutoBypass_ShouldBypass_NonGame(t *testing.T) {
	ab := NewAutoBypass(AutoBypassConfig{Enabled: true})
	if ab.ShouldBypass(`c:\windows\system32\svchost.exe`, "svchost.exe") {
		t.Fatal("expected no bypass for system process")
	}
}

func TestAutoBypass_ShouldBypass_Disabled(t *testing.T) {
	ab := NewAutoBypass(AutoBypassConfig{Enabled: false})
	if ab.ShouldBypass(`e:\steamlibrary\steamapps\common\game\game.exe`, "game.exe") {
		t.Fatal("expected no bypass when disabled")
	}
}

func TestAutoBypass_NeverBypass(t *testing.T) {
	ab := NewAutoBypass(AutoBypassConfig{
		Enabled:     true,
		NeverBypass: []string{"game.exe"},
	})
	if ab.ShouldBypass(`e:\steamlibrary\steamapps\common\game\game.exe`, "game.exe") {
		t.Fatal("expected no bypass for never_bypass exe")
	}
}

func TestAutoBypass_ExtraBypass(t *testing.T) {
	ab := NewAutoBypass(AutoBypassConfig{
		Enabled:     true,
		ExtraBypass: []string{"customgame.exe"},
	})
	if !ab.ShouldBypass(`d:\random\path\customgame.exe`, "customgame.exe") {
		t.Fatal("expected bypass for extra_bypass exe")
	}
}

func TestAutoBypass_ExtraPatterns(t *testing.T) {
	ab := NewAutoBypass(AutoBypassConfig{
		Enabled:       true,
		ExtraPatterns: []string{`d:\mygames`},
	})
	if !ab.ShouldBypass(`d:\mygames\shooter\shooter.exe`, "shooter.exe") {
		t.Fatal("expected bypass for extra_patterns dir")
	}
}

func TestAutoBypass_NeverBypass_OverridesPattern(t *testing.T) {
	ab := NewAutoBypass(AutoBypassConfig{
		Enabled:     true,
		NeverBypass: []string{"crashreporter.exe"},
	})
	if ab.ShouldBypass(`e:\steamlibrary\steamapps\common\game\crashreporter.exe`, "crashreporter.exe") {
		t.Fatal("never_bypass should override directory match")
	}
}

func TestAutoBypass_CacheHit(t *testing.T) {
	ab := NewAutoBypass(AutoBypassConfig{Enabled: true})
	path := `e:\steamlibrary\steamapps\common\game\game.exe`
	r1 := ab.ShouldBypass(path, "game.exe")
	r2 := ab.ShouldBypass(path, "game.exe")
	if r1 != r2 || !r1 {
		t.Fatal("cache should return same result")
	}
}

func TestAutoBypass_ForwardSlash(t *testing.T) {
	ab := NewAutoBypass(AutoBypassConfig{Enabled: true})
	if !ab.ShouldBypass(`e:/steamlibrary/steamapps/common/game/game.exe`, "game.exe") {
		t.Fatal("expected bypass with forward slashes")
	}
}
