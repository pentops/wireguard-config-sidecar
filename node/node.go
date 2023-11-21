package node

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
	b.lines = append(b.lines, line+"\n")
}

func (b *Builder) String() string {
	return strings.Join(b.lines, "")
}

func (b *Builder) ToFile(filepath string) error {
	err := os.WriteFile(filepath, []byte(b.String()), 0600)
	if err != nil {
		return err
	}

	return nil
}
