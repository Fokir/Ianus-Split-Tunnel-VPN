//go:build windows

package core

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
)

// LogLevel represents the severity of a log message.
type LogLevel int

const (
	LevelDebug LogLevel = iota
	LevelInfo
	LevelWarn
	LevelError
	LevelOff
)

// LogConfig holds logging configuration from YAML.
type LogConfig struct {
	Level      string            `yaml:"level,omitempty"`
	Components map[string]string `yaml:"components,omitempty"`
}

// LogHook is a callback invoked for every log message that passes level filtering.
type LogHook func(level LogLevel, tag, message string)

// Logger provides per-component log level filtering.
type Logger struct {
	mu          sync.RWMutex
	globalLevel LogLevel
	components  map[string]LogLevel // lowercase component name → level
	hook        atomic.Pointer[LogHook]
}

// ParseLevel converts a string level name to LogLevel.
// Returns LevelInfo for unrecognized values.
func ParseLevel(s string) LogLevel {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return LevelDebug
	case "info", "":
		return LevelInfo
	case "warn", "warning":
		return LevelWarn
	case "error":
		return LevelError
	case "off", "none":
		return LevelOff
	default:
		return LevelInfo
	}
}

// NewLogger creates a Logger from config.
func NewLogger(cfg LogConfig) *Logger {
	l := &Logger{
		globalLevel: ParseLevel(cfg.Level),
		components:  make(map[string]LogLevel, len(cfg.Components)),
	}
	for name, level := range cfg.Components {
		l.components[strings.ToLower(name)] = ParseLevel(level)
	}
	return l
}

// levelFor returns the effective log level for a component tag.
func (l *Logger) levelFor(tag string) LogLevel {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if lvl, ok := l.components[strings.ToLower(tag)]; ok {
		return lvl
	}
	return l.globalLevel
}

// SetHook installs a callback that receives every log message passing level filtering.
// Pass nil to remove the hook. Only one hook is active at a time.
func (l *Logger) SetHook(h LogHook) {
	if h == nil {
		l.hook.Store(nil)
	} else {
		l.hook.Store(&h)
	}
}

// emit calls the hook if one is installed.
func (l *Logger) emit(level LogLevel, tag, format string, args ...any) {
	if hp := l.hook.Load(); hp != nil {
		msg := fmt.Sprintf(format, args...)
		(*hp)(level, tag, msg)
	}
}

// Debugf logs at debug level.
func (l *Logger) Debugf(tag, format string, args ...any) {
	if l.levelFor(tag) <= LevelDebug {
		log.Printf("["+tag+"] "+format, args...)
		l.emit(LevelDebug, tag, format, args...)
	}
}

// Infof logs at info level.
func (l *Logger) Infof(tag, format string, args ...any) {
	if l.levelFor(tag) <= LevelInfo {
		log.Printf("["+tag+"] "+format, args...)
		l.emit(LevelInfo, tag, format, args...)
	}
}

// Warnf logs at warn level.
func (l *Logger) Warnf(tag, format string, args ...any) {
	if l.levelFor(tag) <= LevelWarn {
		log.Printf("["+tag+"] "+format, args...)
		l.emit(LevelWarn, tag, format, args...)
	}
}

// Errorf logs at error level.
func (l *Logger) Errorf(tag, format string, args ...any) {
	if l.levelFor(tag) <= LevelError {
		log.Printf("["+tag+"] "+format, args...)
		l.emit(LevelError, tag, format, args...)
	}
}

// Fatalf always logs and calls os.Exit(1).
func (l *Logger) Fatalf(tag, format string, args ...any) {
	log.Printf("["+tag+"] "+format, args...)
	l.emit(LevelError, tag, format, args...)
	os.Exit(1)
}

// Log is the global logger instance. Initialized with default (info level).
var Log = NewLogger(LogConfig{})
