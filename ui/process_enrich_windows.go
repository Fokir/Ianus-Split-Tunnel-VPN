//go:build windows

package main

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/color"
	"image/png"
	"sort"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

var (
	shell32 = syscall.NewLazyDLL("shell32.dll")
	user32  = syscall.NewLazyDLL("user32.dll")
	gdi32   = syscall.NewLazyDLL("gdi32.dll")

	pExtractIconExW           = shell32.NewProc("ExtractIconExW")
	pDestroyIcon              = user32.NewProc("DestroyIcon")
	pEnumWindows              = user32.NewProc("EnumWindows")
	pIsWindowVisible          = user32.NewProc("IsWindowVisible")
	pGetWindowTextLengthW     = user32.NewProc("GetWindowTextLengthW")
	pGetWindowThreadProcessId = user32.NewProc("GetWindowThreadProcessId")
	pGetDC                    = user32.NewProc("GetDC")
	pReleaseDC                = user32.NewProc("ReleaseDC")
	pCreateCompatibleDC       = gdi32.NewProc("CreateCompatibleDC")
	pDeleteDC                 = gdi32.NewProc("DeleteDC")
	pCreateDIBSection         = gdi32.NewProc("CreateDIBSection")
	pSelectObject             = gdi32.NewProc("SelectObject")
	pDeleteObject             = gdi32.NewProc("DeleteObject")
	pDrawIconEx               = user32.NewProc("DrawIconEx")
)

type bitmapInfoHeader struct {
	BiSize          uint32
	BiWidth         int32
	BiHeight        int32
	BiPlanes        uint16
	BiBitCount      uint16
	BiCompression   uint32
	BiSizeImage     uint32
	BiXPelsPerMeter int32
	BiYPelsPerMeter int32
	BiClrUsed       uint32
	BiClrImportant  uint32
}

type bitmapInfo struct {
	BmiHeader bitmapInfoHeader
}

var iconCache sync.Map // path (lowercase) -> base64 data URL

// extractProcessIcon extracts the main icon from an exe file and returns
// a "data:image/png;base64,..." string, or empty string on failure.
func extractProcessIcon(exePath string) string {
	if exePath == "" {
		return ""
	}
	key := strings.ToLower(exePath)
	if v, ok := iconCache.Load(key); ok {
		return v.(string)
	}
	icon := doExtractIcon(exePath)
	iconCache.Store(key, icon)
	return icon
}

func doExtractIcon(exePath string) string {
	pathPtr, err := syscall.UTF16PtrFromString(exePath)
	if err != nil {
		return ""
	}

	var hLarge, hSmall uintptr
	ret, _, _ := pExtractIconExW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		0,
		uintptr(unsafe.Pointer(&hLarge)),
		uintptr(unsafe.Pointer(&hSmall)),
		1,
	)
	if ret == 0 {
		return ""
	}

	hIcon := hLarge
	size := 32
	if hIcon == 0 {
		hIcon = hSmall
		size = 16
	}
	if hIcon == 0 {
		return ""
	}

	if hLarge != 0 {
		defer pDestroyIcon.Call(hLarge)
	}
	if hSmall != 0 && hSmall != hLarge {
		defer pDestroyIcon.Call(hSmall)
	}

	data := hIconToPNG(hIcon, size)
	if len(data) == 0 {
		return ""
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(data)
}

func hIconToPNG(hIcon uintptr, size int) []byte {
	hdc, _, _ := pGetDC.Call(0)
	if hdc == 0 {
		return nil
	}
	defer pReleaseDC.Call(0, hdc)

	memDC, _, _ := pCreateCompatibleDC.Call(hdc)
	if memDC == 0 {
		return nil
	}
	defer pDeleteDC.Call(memDC)

	var bmi bitmapInfo
	bmi.BmiHeader.BiSize = uint32(unsafe.Sizeof(bmi.BmiHeader))
	bmi.BmiHeader.BiWidth = int32(size)
	bmi.BmiHeader.BiHeight = -int32(size) // top-down DIB
	bmi.BmiHeader.BiPlanes = 1
	bmi.BmiHeader.BiBitCount = 32

	var bits unsafe.Pointer
	hBitmap, _, _ := pCreateDIBSection.Call(
		memDC,
		uintptr(unsafe.Pointer(&bmi)),
		0, // DIB_RGB_COLORS
		uintptr(unsafe.Pointer(&bits)),
		0, 0,
	)
	if hBitmap == 0 || bits == nil {
		return nil
	}
	defer pDeleteObject.Call(hBitmap)

	old, _, _ := pSelectObject.Call(memDC, hBitmap)
	defer pSelectObject.Call(memDC, old)

	// DI_NORMAL = DI_IMAGE | DI_MASK = 0x0003
	pDrawIconEx.Call(memDC, 0, 0, hIcon,
		uintptr(size), uintptr(size), 0, 0, 3)

	n := size * size
	pixelData := unsafe.Slice((*byte)(bits), n*4)

	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	for i := 0; i < n; i++ {
		off := i * 4
		img.SetNRGBA(i%size, i/size, color.NRGBA{
			R: pixelData[off+2], // BGRA -> RGBA
			G: pixelData[off+1],
			B: pixelData[off],
			A: pixelData[off+3],
		})
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil
	}
	return buf.Bytes()
}

// getWindowedPIDs returns PIDs of processes that have at least one
// visible window with a non-empty title.
func getWindowedPIDs() map[uint32]bool {
	pids := make(map[uint32]bool)

	cb := syscall.NewCallback(func(hwnd, lParam uintptr) uintptr {
		vis, _, _ := pIsWindowVisible.Call(hwnd)
		if vis == 0 {
			return 1
		}
		tLen, _, _ := pGetWindowTextLengthW.Call(hwnd)
		if tLen == 0 {
			return 1
		}
		var pid uint32
		pGetWindowThreadProcessId.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
		if pid != 0 {
			pids[pid] = true
		}
		return 1
	})

	pEnumWindows.Call(cb, 0)
	return pids
}

// enrichProcessList deduplicates processes by exe name, detects which have
// visible windows, extracts icons for windowed ones, and sorts the list
// (windowed first, then alphabetically).
func enrichProcessList(procs []ProcessInfo) []ProcessInfo {
	windowed := getWindowedPIDs()

	type entry struct {
		proc      ProcessInfo
		hasWindow bool
	}
	seen := make(map[string]*entry)
	var order []string

	for i := range procs {
		p := &procs[i]
		key := strings.ToLower(p.Name)
		isW := windowed[p.PID]

		if existing, ok := seen[key]; ok {
			if isW && !existing.hasWindow {
				existing.proc = *p
				existing.hasWindow = true
			} else if p.Path != "" && existing.proc.Path == "" {
				existing.proc.Path = p.Path
				if isW {
					existing.hasWindow = true
				}
			}
		} else {
			seen[key] = &entry{proc: *p, hasWindow: isW}
			order = append(order, key)
		}
	}

	result := make([]ProcessInfo, 0, len(seen))
	for _, key := range order {
		e := seen[key]
		e.proc.HasWindow = e.hasWindow
		if e.hasWindow && e.proc.Path != "" {
			e.proc.Icon = extractProcessIcon(e.proc.Path)
		}
		result = append(result, e.proc)
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].HasWindow != result[j].HasWindow {
			return result[i].HasWindow
		}
		return strings.ToLower(result[i].Name) < strings.ToLower(result[j].Name)
	})

	return result
}
