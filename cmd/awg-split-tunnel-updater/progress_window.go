//go:build windows

package main

import (
	"fmt"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Win32 constants for window creation and messaging.
const (
	wsPopup     = 0x80000000
	wsCaption   = 0x00C00000
	wsVisible   = 0x10000000
	wsChild     = 0x40000000
	wsClipChildren = 0x02000000

	wsExTopmost = 0x00000008

	swShow = 5

	wmDestroy = 0x0002
	wmClose   = 0x0010
	wmSetfont = 0x0030

	wmApp          = 0x8000
	wmUpdateStatus = wmApp + 1
	wmUpdatePct    = wmApp + 2
	wmCloseWindow  = wmApp + 3

	ssLeft       = 0x00000000
	ssCenterImage = 0x00000200

	pbmSetrange32 = 0x0406
	pbmSetpos     = 0x0402
	pbmSetbarcolor = 0x0409

	iccProgressClass = 0x00000020

	colorWindow = 5

	defaultGUI = 17 // DEFAULT_GUI_FONT
)

var (
	moduser32   = windows.NewLazySystemDLL("user32.dll")
	modgdi32    = windows.NewLazySystemDLL("gdi32.dll")
	modcomctl32 = windows.NewLazySystemDLL("comctl32.dll")

	procRegisterClassExW    = moduser32.NewProc("RegisterClassExW")
	procCreateWindowExW     = moduser32.NewProc("CreateWindowExW")
	procDefWindowProcW      = moduser32.NewProc("DefWindowProcW")
	procGetMessageW         = moduser32.NewProc("GetMessageW")
	procTranslateMessage    = moduser32.NewProc("TranslateMessage")
	procDispatchMessageW    = moduser32.NewProc("DispatchMessageW")
	procPostMessageW        = moduser32.NewProc("PostMessageW")
	procDestroyWindow       = moduser32.NewProc("DestroyWindow")
	procPostQuitMessage     = moduser32.NewProc("PostQuitMessage")
	procShowWindow          = moduser32.NewProc("ShowWindow")
	procUpdateWindow        = moduser32.NewProc("UpdateWindow")
	procSendMessageW        = moduser32.NewProc("SendMessageW")
	procSetWindowTextW      = moduser32.NewProc("SetWindowTextW")
	procGetSystemMetrics    = moduser32.NewProc("GetSystemMetrics")
	procSetWindowPos        = moduser32.NewProc("SetWindowPos")
	procGetStockObject      = modgdi32.NewProc("GetStockObject")
	procInitCommonControlsEx = modcomctl32.NewProc("InitCommonControlsEx")
)

type wndClassExW struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     windows.Handle
	HIcon         windows.Handle
	HCursor       windows.Handle
	HbrBackground windows.Handle
	LpszMenuName  *uint16
	LpszClassName *uint16
	HIconSm       windows.Handle
}

type point struct {
	X, Y int32
}

type msg struct {
	HWnd    windows.Handle
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      point
}

type initCommonControlsExInfo struct {
	DwSize uint32
	DwICC  uint32
}

// ProgressWindow displays a non-closable progress window during update.
type ProgressWindow struct {
	hwnd       windows.Handle
	hwndStatus windows.Handle
	hwndPct    windows.Handle
	hwndBar    windows.Handle
	ready      chan struct{}
	done       chan struct{}
	once       sync.Once
}

// Global reference for the WndProc callback.
var globalPW *ProgressWindow

func NewProgressWindow() *ProgressWindow {
	return &ProgressWindow{
		ready: make(chan struct{}),
		done:  make(chan struct{}),
	}
}

// Show creates and displays the progress window in a dedicated OS thread.
// It blocks internally; call from a goroutine. Wait on pw.ready before sending updates.
func (pw *ProgressWindow) Show() {
	globalPW = pw

	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		// Init common controls for progress bar.
		icc := initCommonControlsExInfo{
			DwSize: uint32(unsafe.Sizeof(initCommonControlsExInfo{})),
			DwICC:  iccProgressClass,
		}
		procInitCommonControlsEx.Call(uintptr(unsafe.Pointer(&icc)))

		hInst := windows.Handle(0)
		className, _ := windows.UTF16PtrFromString("AWGUpdaterProgress")

		wc := wndClassExW{
			CbSize:        uint32(unsafe.Sizeof(wndClassExW{})),
			Style:         3, // CS_HREDRAW | CS_VREDRAW
			LpfnWndProc:   syscall.NewCallback(wndProc),
			HInstance:     hInst,
			HbrBackground: windows.Handle(colorWindow + 1),
			LpszClassName: className,
		}
		procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))

		// Window size.
		const winW, winH = 420, 140

		// Center on screen.
		screenW, _, _ := procGetSystemMetrics.Call(0) // SM_CXSCREEN
		screenH, _, _ := procGetSystemMetrics.Call(1) // SM_CYSCREEN
		x := (int32(screenW) - winW) / 2
		y := (int32(screenH) - winH) / 2

		title, _ := windows.UTF16PtrFromString("AWG Split Tunnel — Updating...")

		// WS_POPUP | WS_CAPTION | WS_VISIBLE | WS_CLIPCHILDREN — no WS_SYSMENU, so no close button.
		style := uint32(wsPopup | wsCaption | wsVisible | wsClipChildren)

		hwnd, _, _ := procCreateWindowExW.Call(
			uintptr(wsExTopmost),
			uintptr(unsafe.Pointer(className)),
			uintptr(unsafe.Pointer(title)),
			uintptr(style),
			uintptr(x), uintptr(y),
			uintptr(winW), uintptr(winH),
			0, 0, 0, 0,
		)
		pw.hwnd = windows.Handle(hwnd)

		font, _, _ := procGetStockObject.Call(uintptr(defaultGUI))

		// Status label — top area.
		staticClass, _ := windows.UTF16PtrFromString("STATIC")
		initText, _ := windows.UTF16PtrFromString("Preparing update...")
		h, _, _ := procCreateWindowExW.Call(
			0,
			uintptr(unsafe.Pointer(staticClass)),
			uintptr(unsafe.Pointer(initText)),
			uintptr(wsChild|wsVisible|ssLeft|ssCenterImage),
			20, 15, 380, 24,
			hwnd, 0, 0, 0,
		)
		pw.hwndStatus = windows.Handle(h)
		procSendMessageW.Call(h, wmSetfont, font, 1)

		// Percentage label — right side of progress bar.
		pctText, _ := windows.UTF16PtrFromString("0%")
		h2, _, _ := procCreateWindowExW.Call(
			0,
			uintptr(unsafe.Pointer(staticClass)),
			uintptr(unsafe.Pointer(pctText)),
			uintptr(wsChild|wsVisible|ssLeft|ssCenterImage),
			360, 55, 40, 24,
			hwnd, 0, 0, 0,
		)
		pw.hwndPct = windows.Handle(h2)
		procSendMessageW.Call(h2, wmSetfont, font, 1)

		// Progress bar.
		progressClass, _ := windows.UTF16PtrFromString("msctls_progress32")
		h3, _, _ := procCreateWindowExW.Call(
			0,
			uintptr(unsafe.Pointer(progressClass)),
			0,
			uintptr(wsChild|wsVisible),
			20, 55, 330, 24,
			hwnd, 0, 0, 0,
		)
		pw.hwndBar = windows.Handle(h3)
		// Set range 0–100.
		procSendMessageW.Call(h3, pbmSetrange32, 0, 100)

		procShowWindow.Call(hwnd, swShow)
		procUpdateWindow.Call(hwnd)

		close(pw.ready)

		// Message loop.
		var m msg
		for {
			ret, _, _ := procGetMessageW.Call(
				uintptr(unsafe.Pointer(&m)), 0, 0, 0,
			)
			if int32(ret) <= 0 {
				break
			}
			procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
			procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
		}

		close(pw.done)
	}()

	<-pw.ready
}

// SetStatus updates the status text shown in the window.
func (pw *ProgressWindow) SetStatus(text string) {
	if pw.hwnd == 0 {
		return
	}
	ptr, _ := windows.UTF16PtrFromString(text)
	procSetWindowTextW.Call(uintptr(pw.hwndStatus), uintptr(unsafe.Pointer(ptr)))
}

// SetProgress sets the progress bar value (0–100) and updates the percentage label.
func (pw *ProgressWindow) SetProgress(pct int) {
	if pw.hwnd == 0 {
		return
	}
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	procSendMessageW.Call(uintptr(pw.hwndBar), pbmSetpos, uintptr(pct), 0)

	label := fmt.Sprintf("%d%%", pct)
	ptr, _ := windows.UTF16PtrFromString(label)
	procSetWindowTextW.Call(uintptr(pw.hwndPct), uintptr(unsafe.Pointer(ptr)))
}

// Close destroys the progress window.
func (pw *ProgressWindow) Close() {
	pw.once.Do(func() {
		if pw.hwnd != 0 {
			procPostMessageW.Call(uintptr(pw.hwnd), wmCloseWindow, 0, 0)
			<-pw.done
		}
	})
}

// wndProc is the window procedure for the progress window.
func wndProc(hwnd uintptr, msg uint32, wParam, lParam uintptr) uintptr {
	switch msg {
	case wmClose:
		// Ignore close — window cannot be closed by the user.
		return 0
	case wmCloseWindow:
		procDestroyWindow.Call(hwnd)
		return 0
	case wmDestroy:
		procPostQuitMessage.Call(0)
		return 0
	}
	ret, _, _ := procDefWindowProcW.Call(hwnd, uintptr(msg), wParam, lParam)
	return ret
}
