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
	globalLevel LogLevel
	components  map[string]LogLevel // lowercase component name → level (immutable after init)
	levelCache  sync.Map            // tag → LogLevel (lock-free cache)
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
// Results are cached lock-free after the first lookup per tag.
func (l *Logger) levelFor(tag string) LogLevel {
	if v, ok := l.levelCache.Load(tag); ok {
		return v.(LogLevel)
	}
	// Slow path: normalize + lookup + cache.
	lvl := l.globalLevel
	if cl, ok := l.components[strings.ToLower(tag)]; ok {
		lvl = cl
	}
	l.levelCache.Store(tag, lvl)
	return lvl
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

// emit calls the hook if one is installed. Accepts a pre-formatted message.
func (l *Logger) emit(level LogLevel, tag, msg string) {
	if hp := l.hook.Load(); hp != nil {
		(*hp)(level, tag, msg)
	}
}

// Debugf logs at debug level.
func (l *Logger) Debugf(tag, format string, args ...any) {
	if l.levelFor(tag) <= LevelDebug {
		msg := fmt.Sprintf(format, args...)
		log.Printf("[%s] %s", tag, msg)
		l.emit(LevelDebug, tag, msg)
	}
}

// Infof logs at info level.
func (l *Logger) Infof(tag, format string, args ...any) {
	if l.levelFor(tag) <= LevelInfo {
		msg := fmt.Sprintf(format, args...)
		log.Printf("[%s] %s", tag, msg)
		l.emit(LevelInfo, tag, msg)
	}
}

// Warnf logs at warn level.
func (l *Logger) Warnf(tag, format string, args ...any) {
	if l.levelFor(tag) <= LevelWarn {
		msg := fmt.Sprintf(format, args...)
		log.Printf("[%s] %s", tag, msg)
		l.emit(LevelWarn, tag, msg)
	}
}

// Errorf logs at error level.
func (l *Logger) Errorf(tag, format string, args ...any) {
	if l.levelFor(tag) <= LevelError {
		msg := fmt.Sprintf(format, args...)
		log.Printf("[%s] %s", tag, msg)
		l.emit(LevelError, tag, msg)
	}
}

// Fatalf always logs and calls os.Exit(1).
func (l *Logger) Fatalf(tag, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	log.Printf("[%s] %s", tag, msg)
	l.emit(LevelError, tag, msg)
	os.Exit(1)
}

// Log is the global logger instance. Initialized with default (info level).
var Log = NewLogger(LogConfig{})
