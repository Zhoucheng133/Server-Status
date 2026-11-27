//go:build unix

package main

import (
	"fmt"
	"os"
	"syscall"
)

func logFileID(info os.FileInfo) string {
	stat := info.Sys().(*syscall.Stat_t)
	return fmt.Sprintf("%d:%d", stat.Dev, stat.Ino)
}
