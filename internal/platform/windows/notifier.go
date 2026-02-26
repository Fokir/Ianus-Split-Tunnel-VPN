//go:build windows

package windows

import (
	"os/exec"
	"syscall"

	"awg-split-tunnel/internal/core"
)

// Notifier implements platform.Notifier using Windows toast notifications
// via PowerShell (no external dependency required).
type Notifier struct{}

// Show displays a system notification using PowerShell toast API.
func (n *Notifier) Show(title, message string) error {
	script := `
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
$template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
$text = $template.GetElementsByTagName("text")
$text.Item(0).AppendChild($template.CreateTextNode("` + title + `")) > $null
$text.Item(1).AppendChild($template.CreateTextNode("` + message + `")) > $null
$toast = [Windows.UI.Notifications.ToastNotification]::new($template)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("AWG Split Tunnel").Show($toast)
`
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmd.Run(); err != nil {
		core.Log.Warnf("Notifier", "Toast notification failed: %v", err)
		return err
	}
	return nil
}
