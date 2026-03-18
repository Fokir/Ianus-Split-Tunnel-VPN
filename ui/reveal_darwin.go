//go:build darwin

package main

import "os/exec"

func revealInExplorerOS(filePath string) error {
	return exec.Command("open", "-R", filePath).Start()
}
