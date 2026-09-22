package banner

import (
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

const innerWidth = 46

func Print(w io.Writer) {
	art := []string{
		`__      _________`,
		`\ \    / /__   __|`,
		` \ \  / /   | |`,
		`  \ \/ /    | |`,
		`   \  /     | |`,
		`    \/      |_|`,
	}

	lines := make([]string, 0, len(art)+6)
	lines = append(lines, padBlock(art)...)
	lines = append(lines, "")
	lines = append(lines, "VT")
	lines = append(lines, "VirusTotal Domain Recon")
	lines = append(lines, "Author: A-TURBO-99")

	border := "+" + strings.Repeat("-", innerWidth) + "+"
	fmt.Fprintln(w, border)
	fmt.Fprintln(w, "|"+strings.Repeat(" ", innerWidth)+"|")
	for _, line := range lines {
		fmt.Fprintln(w, "|"+center(line, innerWidth)+"|")
	}
	fmt.Fprintln(w, "|"+strings.Repeat(" ", innerWidth)+"|")
	fmt.Fprintln(w, border)
}

func padBlock(lines []string) []string {
	max := 0
	for _, line := range lines {
		if n := utf8.RuneCountInString(line); n > max {
			max = n
		}
	}
	out := make([]string, len(lines))
	for i, line := range lines {
		out[i] = line + strings.Repeat(" ", max-utf8.RuneCountInString(line))
	}
	return out
}

func center(s string, width int) string {
	n := utf8.RuneCountInString(s)
	if n >= width {
		runes := []rune(s)
		return string(runes[:width])
	}
	left := (width - n) / 2
	right := width - n - left
	return strings.Repeat(" ", left) + s + strings.Repeat(" ", right)
}
