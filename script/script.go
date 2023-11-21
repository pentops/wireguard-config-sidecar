package script

import (
	"os"
	"strings"
)

type Builder struct {
	lines []string
}

func NewBuilder() *Builder {
	return &Builder{}
}

func (b *Builder) AddLine(line string) {
	b.lines = append(b.lines, line)
}

func (b *Builder) ToOneLine() string {
	return strings.Join(b.lines, ";")
}

func (b *Builder) ToMultiline() string {
	return strings.Join(b.lines, "\n")
}

func (b *Builder) ToFile(filepath string) error {
	c := "#!/bin/bash\n\n" + b.ToMultiline()

	err := os.WriteFile(filepath, []byte(c), 0744)
	if err != nil {
		return err
	}

	return nil
}
