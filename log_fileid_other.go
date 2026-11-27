//go:build !unix

package main

import "os"

// Rotation is detected by the live file handle and the saved checkpoint signature.
func logFileID(info os.FileInfo) string { return info.Name() }
