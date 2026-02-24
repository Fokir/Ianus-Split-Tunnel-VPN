//go:build windows

package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

var diagLog *log.Logger

// lazyLogWriter creates the log file only on the first Write call,
// so commands that produce no log output (e.g. "version") don't leave empty files.
type lazyLogWriter struct {
	mu       sync.Mutex
	filePath string
	file     *os.File
}

func (w *lazyLogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file == nil {
		// Ensure the logs directory exists.
		if err := os.MkdirAll(filepath.Dir(w.filePath), 0o755); err != nil {
			return 0, fmt.Errorf("create logs dir: %w", err)
		}
		f, err := os.Create(w.filePath)
		if err != nil {
			return 0, fmt.Errorf("create log file: %w", err)
		}
		w.file = f
	}
	return w.file.Write(p)
}

func (w *lazyLogWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file != nil {
		return w.file.Close()
	}
	return nil
}

// initLogger sets up the diagLog logger with a lazy file writer.
// The log file is only created when actual output is written.
func initLogger() (*lazyLogWriter, error) {
	exeDir := exeDirectory()
	logsDir := filepath.Join(exeDir, "logs")
	name := time.Now().Format("02-01-2006-15-04-05") + ".log"
	path := filepath.Join(logsDir, name)

	lw := &lazyLogWriter{filePath: path}

	// When --json is enabled, only write logs to file to keep stdout clean for JSON.
	var w io.Writer
	if jsonOutput {
		w = lw
	} else {
		w = io.MultiWriter(os.Stdout, lw)
	}
	diagLog = log.New(w, "", log.LstdFlags)
	return lw, nil
}

// exeDirectory returns the directory containing the running executable.
func exeDirectory() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}

// logsDirectory returns the path to the logs/ folder.
func logsDirectory() string {
	return filepath.Join(exeDirectory(), "logs")
}

// runLogsList shows log files sorted by modification time (newest first).
func runLogsList() {
	entries, err := os.ReadDir(logsDirectory())
	if err != nil {
		fatal("read logs directory: %v", err)
	}

	type logEntry struct {
		Name    string `json:"name"`
		Size    int64  `json:"size"`
		ModTime string `json:"mod_time"`
	}

	var logs []logEntry
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".log") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		logs = append(logs, logEntry{
			Name:    e.Name(),
			Size:    info.Size(),
			ModTime: info.ModTime().Format(time.RFC3339),
		})
	}

	// Sort newest first.
	sort.Slice(logs, func(i, j int) bool {
		return logs[i].ModTime > logs[j].ModTime
	})

	if jsonOutput {
		outputJSON(logs)
		return
	}

	if len(logs) == 0 {
		fmt.Println("No log files found.")
		return
	}

	fmt.Printf("%-30s %10s  %s\n", "FILE", "SIZE", "MODIFIED")
	fmt.Printf("%s\n", strings.Repeat("-", 60))
	for _, l := range logs {
		fmt.Printf("%-30s %10d  %s\n", l.Name, l.Size, l.ModTime)
	}
}

// runLogsTail prints the last N lines of the most recent log file.
func runLogsTail(lines int) {
	dir := logsDirectory()
	entries, err := os.ReadDir(dir)
	if err != nil {
		fatal("read logs directory: %v", err)
	}

	// Collect .log files sorted by mod time (newest first).
	type logFile struct {
		name    string
		modTime time.Time
		size    int64
	}
	var logFiles []logFile
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".log") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		logFiles = append(logFiles, logFile{
			name:    e.Name(),
			modTime: info.ModTime(),
			size:    info.Size(),
		})
	}
	sort.Slice(logFiles, func(i, j int) bool {
		return logFiles[i].modTime.After(logFiles[j].modTime)
	})

	// Pick the newest non-empty file (skip the current invocation's empty log).
	var newest string
	for _, lf := range logFiles {
		if lf.size > 0 {
			newest = lf.name
			break
		}
	}
	// Fallback to newest regardless.
	if newest == "" && len(logFiles) > 0 {
		newest = logFiles[0].name
	}
	if newest == "" {
		fatal("no log files found")
	}

	path := filepath.Join(dir, newest)
	f, err := os.Open(path)
	if err != nil {
		fatal("open log file: %v", err)
	}
	defer f.Close()

	// Read all lines and take the last N.
	var allLines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		allLines = append(allLines, scanner.Text())
	}

	if !jsonOutput {
		fmt.Printf("=== %s ===\n", newest)
	}

	start := 0
	if len(allLines) > lines {
		start = len(allLines) - lines
	}
	tail := allLines[start:]

	if jsonOutput {
		outputJSON(map[string]any{
			"file":  newest,
			"lines": tail,
		})
		return
	}

	for _, line := range tail {
		fmt.Println(line)
	}
}

// runLogsClean removes old log files, keeping the N newest.
func runLogsClean(keep int) {
	dir := logsDirectory()
	entries, err := os.ReadDir(dir)
	if err != nil {
		fatal("read logs directory: %v", err)
	}

	type fileInfo struct {
		name    string
		modTime time.Time
	}

	var logs []fileInfo
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".log") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		logs = append(logs, fileInfo{name: e.Name(), modTime: info.ModTime()})
	}

	// Sort newest first.
	sort.Slice(logs, func(i, j int) bool {
		return logs[i].modTime.After(logs[j].modTime)
	})

	removed := 0
	for i, l := range logs {
		if i < keep {
			continue
		}
		path := filepath.Join(dir, l.name)
		if err := os.Remove(path); err != nil {
			diagLog.Printf("Warning: could not remove %s: %v", l.name, err)
			continue
		}
		removed++
	}

	diagLog.Printf("Cleaned %d log file(s), kept %d newest", removed, min(keep, len(logs)))
}
