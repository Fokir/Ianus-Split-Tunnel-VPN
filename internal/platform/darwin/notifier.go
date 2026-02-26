//go:build darwin

package darwin

import (
	"fmt"
	"os/exec"
)

// Notifier implements platform.Notifier using macOS osascript.
type Notifier struct{}

// Show displays a macOS system notification using osascript.
func (n *Notifier) Show(title, message string) error {
	script := fmt.Sprintf(`display notification %q with title %q`, message, title)
	return exec.Command("osascript", "-e", script).Run()
}
