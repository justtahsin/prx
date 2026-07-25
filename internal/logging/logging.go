// Package logging builds the loggers both binaries use.
package logging

import (
	"log/slog"
	"os"
	"strings"
)

// New returns a logger writing human-readable lines to stderr at the given
// level ("error", "warn", "info" or "debug").
func New(level string) *slog.Logger {
	var lvl slog.Level
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "error":
		lvl = slog.LevelError
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "debug":
		lvl = slog.LevelDebug
	default:
		lvl = slog.LevelInfo
	}

	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: lvl,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			// Timestamps come from the journal or the terminal already.
			if a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		},
	}))
}
