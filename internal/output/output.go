package output

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type Writer struct {
	stdout io.Writer
	stderr io.Writer
	file   io.WriteCloser
	buf    *bufio.Writer
}

func New(stdout, stderr io.Writer, path string) (*Writer, error) {
	w := &Writer{
		stdout: stdout,
		stderr: stderr,
	}
	if path == "" {
		return w, nil
	}

	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("unable to create output directory for %s: %w", path, err)
		}
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, fmt.Errorf("unable to write output file %s: %w", path, err)
	}
	w.file = f
	w.buf = bufio.NewWriter(f)
	return w, nil
}

func (w *Writer) Statusf(format string, args ...any) {
	fmt.Fprintf(w.stderr, format+"\n", args...)
}

func (w *Writer) Errorf(format string, args ...any) {
	fmt.Fprintf(w.stderr, "[-] "+format+"\n", args...)
}

func (w *Writer) WriteResults(values []string) error {
	for _, v := range values {
		if v == "" {
			continue
		}
		if _, err := fmt.Fprintln(w.stdout, v); err != nil {
			return fmt.Errorf("failed writing results to stdout: %w", err)
		}
		if w.buf != nil {
			if _, err := w.buf.WriteString(v + "\n"); err != nil {
				return fmt.Errorf("failed writing results to output file: %w", err)
			}
		}
	}
	return nil
}

func (w *Writer) BlankLine() error {
	if _, err := fmt.Fprintln(w.stdout); err != nil {
		return fmt.Errorf("failed writing results to stdout: %w", err)
	}
	if w.buf != nil {
		if err := w.buf.WriteByte('\n'); err != nil {
			return fmt.Errorf("failed writing results to output file: %w", err)
		}
	}
	return nil
}

func (w *Writer) Close() error {
	if w.buf != nil {
		if err := w.buf.Flush(); err != nil {
			if w.file != nil {
				_ = w.file.Close()
			}
			return fmt.Errorf("failed flushing output file: %w", err)
		}
	}
	if w.file != nil {
		if err := w.file.Close(); err != nil {
			return fmt.Errorf("failed closing output file: %w", err)
		}
	}
	return nil
}
