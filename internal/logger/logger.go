package logger

import (
	"encoding/json"
	"io"
	"os"
	"time"

	"github.com/Pirikara/chaingate/internal/ecosystem"
	"github.com/Pirikara/chaingate/internal/policy"
)

// Level represents log level
type Level string

const (
	LevelDebug Level = "debug"
	LevelInfo  Level = "info"
	LevelWarn  Level = "warn"
	LevelError Level = "error"
)

// Logger provides JSON Lines logging
type Logger struct {
	writer io.Writer
	level  Level
}

// NewLogger creates a new Logger
func NewLogger(writer io.Writer, level Level) *Logger {
	if writer == nil {
		writer = os.Stdout
	}
	return &Logger{
		writer: writer,
		level:  level,
	}
}

// MalwareFindingLog represents a malware finding for logging
type MalwareFindingLog struct {
	ID      string `json:"id"`
	Summary string `json:"summary"`
	Source  string `json:"source"`
}

// PackageCheckEvent represents a package check event
type PackageCheckEvent struct {
	Timestamp       string              `json:"ts"`
	Level           string              `json:"level"`
	Event           string              `json:"event"`
	Ecosystem       string              `json:"ecosystem"`
	Name            string              `json:"name"`
	Version         string              `json:"version"`
	MalwareFindings []MalwareFindingLog `json:"malware_findings"`
	Decision        string              `json:"decision"`
	Mode            string              `json:"mode"`
	CI              bool                `json:"ci"`
	RequestID       string              `json:"request_id,omitempty"`
}

// LogPackageCheck logs a package check event
func (l *Logger) LogPackageCheck(
	pkg *ecosystem.PackageIdentity,
	intel *policy.ThreatIntelResult,
	decision policy.Decision,
	mode policy.Mode,
	isCI bool,
	requestID string,
) {
	// Convert malware findings to log format
	findings := make([]MalwareFindingLog, len(intel.MalwareFindings))
	for i, f := range intel.MalwareFindings {
		findings[i] = MalwareFindingLog{
			ID:      f.ID,
			Summary: f.Summary,
			Source:  f.Source,
		}
	}

	event := PackageCheckEvent{
		Timestamp:       time.Now().UTC().Format(time.RFC3339Nano),
		Level:           string(LevelInfo),
		Event:           "package_check",
		Ecosystem:       string(pkg.Ecosystem),
		Name:            pkg.Name,
		Version:         pkg.Version,
		MalwareFindings: findings,
		Decision:        string(decision),
		Mode:            string(mode),
		CI:              isCI,
		RequestID:       requestID,
	}

	if findings == nil {
		event.MalwareFindings = []MalwareFindingLog{}
	}

	l.writeJSON(event)
}

// GenericEvent represents a generic log event
type GenericEvent struct {
	Timestamp string                 `json:"ts"`
	Level     string                 `json:"level"`
	Event     string                 `json:"event"`
	Message   string                 `json:"message,omitempty"`
	Data      map[string]interface{} `json:"data,omitempty"`
}

// Log logs a generic event
func (l *Logger) Log(level Level, event, message string, data map[string]interface{}) {
	e := GenericEvent{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Level:     string(level),
		Event:     event,
		Message:   message,
		Data:      data,
	}

	l.writeJSON(e)
}

// Debug logs a debug event
func (l *Logger) Debug(event, message string, data map[string]interface{}) {
	if l.shouldLog(LevelDebug) {
		l.Log(LevelDebug, event, message, data)
	}
}

// Info logs an info event
func (l *Logger) Info(event, message string, data map[string]interface{}) {
	if l.shouldLog(LevelInfo) {
		l.Log(LevelInfo, event, message, data)
	}
}

// Warn logs a warning event
func (l *Logger) Warn(event, message string, data map[string]interface{}) {
	if l.shouldLog(LevelWarn) {
		l.Log(LevelWarn, event, message, data)
	}
}

// Error logs an error event
func (l *Logger) Error(event, message string, data map[string]interface{}) {
	if l.shouldLog(LevelError) {
		l.Log(LevelError, event, message, data)
	}
}

// writeJSON writes a JSON line to the output
func (l *Logger) writeJSON(v interface{}) {
	data, err := json.Marshal(v)
	if err != nil {
		// Fallback to stderr if marshal fails
		os.Stderr.WriteString("Failed to marshal log: " + err.Error() + "\n")
		return
	}

	l.writer.Write(data)
	l.writer.Write([]byte("\n"))
}

// shouldLog checks if a log level should be logged
func (l *Logger) shouldLog(level Level) bool {
	levels := map[Level]int{
		LevelDebug: 0,
		LevelInfo:  1,
		LevelWarn:  2,
		LevelError: 3,
	}

	return levels[level] >= levels[l.level]
}
