//go:build windows

package main

import "syscall"

const enableVTMode = 0x0004

var setConsoleMode = syscall.NewLazyDLL("kernel32.dll").NewProc("SetConsoleMode")

// enableVT switches on ENABLE_VIRTUAL_TERMINAL_PROCESSING so ANSI escape
// sequences render as color and movement on Windows consoles instead of
// leaking raw text.
func enableVT() bool {
	handle, err := syscall.GetStdHandle(syscall.STD_OUTPUT_HANDLE)
	if err != nil {
		return false
	}
	var mode uint32
	if err := syscall.GetConsoleMode(handle, &mode); err != nil {
		return false
	}
	ret, _, _ := setConsoleMode.Call(uintptr(handle), uintptr(mode|enableVTMode))
	return ret != 0
}
