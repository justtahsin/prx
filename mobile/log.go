package prxmobile

import (
	"io"
	"log/slog"
	"strings"
)

// newLogger bridges the Go client's structured logging to whatever the app
// supplied, or discards it when the app supplied nothing.
func newLogger(logger Logger) *slog.Logger {
	var out io.Writer = io.Discard
	if logger != nil {
		out = logWriter{logger: logger}
	}

	return slog.New(slog.NewTextHandler(out, &slog.HandlerOptions{
		Level: slog.LevelInfo,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			// Android's log already timestamps every line.
			if a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		},
	}))
}

// logWriter turns each handler write into one call across the bridge.
// slog serialises writes internally, so no locking is needed here.
type logWriter struct{ logger Logger }

func (w logWriter) Write(p []byte) (int, error) {
	w.logger.Log(strings.TrimRight(string(p), "\n"))
	return len(p), nil
}
