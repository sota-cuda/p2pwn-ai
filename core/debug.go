package core

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// DebugLogger writes detailed activity logs to debug.txt in the output folder.
// It is safe for concurrent use and can be toggled at runtime with SetEnabled.
type DebugLogger struct {
	mu      sync.Mutex
	file    *os.File
	enabled bool
}

var dbg = &DebugLogger{}

// InitDebug opens <outDir>/debug.txt for appending if debug mode is enabled.
func InitDebug(outDir string, enabled bool) {
	dbg.mu.Lock()
	defer dbg.mu.Unlock()

	dbg.enabled = enabled
	if !enabled {
		return
	}

	if err := os.MkdirAll(outDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "[debug] cannot create output dir: %v\n", err)
		return
	}

	path := filepath.Join(outDir, "debug.txt")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[debug] cannot open %s: %v\n", path, err)
		return
	}
	dbg.file = f

	nowStr := time.Now().Format("02-01-2006 15:04:05")
	fmt.Fprintf(f, "# [%s] Debug logging started\n", nowStr)
}

// CloseDebug flushes and closes the debug log file.
func CloseDebug() {
	dbg.mu.Lock()
	defer dbg.mu.Unlock()

	if dbg.file != nil {
		nowStr := time.Now().Format("02-01-2006 15:04:05")
		fmt.Fprintf(dbg.file, "# [%s] Debug logging finished\n", nowStr)
		dbg.file.Close()
		dbg.file = nil
	}
	dbg.enabled = false
}

// Debugf logs a formatted message to debug.txt when debug mode is on.
func Debugf(format string, args ...interface{}) {
	dbg.mu.Lock()
	defer dbg.mu.Unlock()

	if !dbg.enabled || dbg.file == nil {
		return
	}

	nowStr := time.Now().Format("15:04:05")
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(dbg.file, "[%s] %s\n", nowStr, msg)
}
