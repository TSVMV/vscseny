//go:build !windows

package main

// enableVT turns on ANSI escape processing for the terminal. Unix consoles
// accept escape sequences by default, so there is nothing to switch on.
func enableVT() bool {
	return true
}
