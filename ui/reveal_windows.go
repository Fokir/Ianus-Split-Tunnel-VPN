//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

var procShellExecuteW = syscall.NewLazyDLL("shell32.dll").NewProc("ShellExecuteW")

func revealInExplorerOS(filePath string) error {
	verb, _ := syscall.UTF16PtrFromString("open")
	file, _ := syscall.UTF16PtrFromString("explorer.exe")
	args, _ := syscall.UTF16PtrFromString("/select," + filePath)

	ret, _, err := procShellExecuteW.Call(
		0,
		uintptr(unsafe.Pointer(verb)),
		uintptr(unsafe.Pointer(file)),
		uintptr(unsafe.Pointer(args)),
		0,
		syscall.SW_SHOWNORMAL,
	)
	if ret <= 32 {
		return err
	}
	return nil
}
