//go:build darwin

package main

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Cocoa
#import <Cocoa/Cocoa.h>

// Adds NSWindowStyleMaskMiniaturizable to every existing NSWindow so that
// [NSWindow miniaturize:] (invoked via Wails Window.Minimise()) actually
// sweeps the window into the Dock. Wails creates frameless windows with
// the borderless style mask, which omits the miniaturizable bit.
static void enableMinimiseOnAllWindows() {
    dispatch_async(dispatch_get_main_queue(), ^{
        for (NSWindow *w in [NSApp windows]) {
            [w setStyleMask:[w styleMask] | NSWindowStyleMaskMiniaturizable];
        }
    });
}
*/
import "C"

func enableMinimiseStyle() {
	C.enableMinimiseOnAllWindows()
}
