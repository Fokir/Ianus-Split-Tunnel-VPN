//go:build windows

package main

import (
	"log"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	singleInstanceMutex = "Global\\AWGSplitTunnelUI"
	wmUser              = 0x0400
	wmShowUI            = wmUser + 0x0100
)

// acquireSingleInstance tries to create a named mutex.
// Returns true if this is the first instance, false if another is already running.
func acquireSingleInstance() bool {
	name, _ := windows.UTF16PtrFromString(singleInstanceMutex)
	h, err := windows.CreateMutex(nil, false, name)
	if err == windows.ERROR_ALREADY_EXISTS {
		if h != 0 {
			windows.CloseHandle(h)
		}
		return false
	}
	if h == 0 {
		log.Printf("[UI] CreateMutex failed: %v", err)
		return true // proceed anyway on unexpected error
	}
	// Keep the handle open for the lifetime of the process (closed on exit).
	return true
}

const hwndBroadcast = 0xFFFF

// notifyExistingInstance broadcasts a custom message so the running instance
// can bring its window to the foreground.
func notifyExistingInstance() {
	procPostMessage := user32.NewProc("PostMessageW")
	procPostMessage.Call(hwndBroadcast, wmShowUI, 0, 0)
}

// registerWindowMessageHook creates a hidden message-only window that
// listens for wmShowUI and shows the main Wails window.
func registerWindowMessageHook(showFn func()) {
	go createMessageWindow(showFn)
}

var (
	procDefWindowProcW   = user32.NewProc("DefWindowProcW")
	procRegisterClassExW = user32.NewProc("RegisterClassExW")
	procCreateWindowExW  = user32.NewProc("CreateWindowExW")
	procGetMessageW      = user32.NewProc("GetMessageW")
	procTranslateMessage = user32.NewProc("TranslateMessage")
	procDispatchMessageW = user32.NewProc("DispatchMessageW")
)

func createMessageWindow(showFn func()) {
	const className = "AWGSplitTunnelMsgWindow"

	hInstance, _, _ := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetModuleHandleW").Call(0)

	classNamePtr, _ := windows.UTF16PtrFromString(className)

	wndProc := windows.NewCallback(func(hwnd uintptr, msg uint32, wParam, lParam uintptr) uintptr {
		if msg == wmShowUI {
			showFn()
			return 0
		}
		ret, _, _ := procDefWindowProcW.Call(hwnd, uintptr(msg), wParam, lParam)
		return ret
	})

	var wc wndClassExW
	wc.CbSize = uint32(unsafe.Sizeof(wc))
	wc.LpfnWndProc = wndProc
	wc.HInstance = hInstance
	wc.LpszClassName = classNamePtr

	procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))

	hwndMessageOnly := ^uintptr(2) // HWND_MESSAGE = (HWND)-3
	procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(classNamePtr)),
		0,
		0,
		0, 0, 0, 0,
		hwndMessageOnly,
		0,
		hInstance,
		0,
	)

	// Message pump for this thread.
	var msg msgT
	for {
		ret, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if ret == 0 || ret == ^uintptr(0) {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
	}
}

// Win32 types for the message-only window.
type wndClassExW struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     uintptr
	HIcon         uintptr
	HCursor       uintptr
	HbrBackground uintptr
	LpszMenuName  *uint16
	LpszClassName *uint16
	HIconSm       uintptr
}

type msgT struct {
	Hwnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      point
}

type point struct {
	X, Y int32
}
