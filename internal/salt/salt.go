// Package salt provides utilities for generating salts.
package salt

import (
	"crypto/rand"
	"fmt"
	"io"
)

const RecommendedSize = 16

var Reader = rand.Reader

func New(from io.Reader, size uint32) ([]byte, error) {
	salt := make([]byte, size)

	if _, err := from.Read(salt); err != nil {
		return nil, fmt.Errorf("salt: %w", err)
	}

	return salt, nil
}

// ErrReader can be used to mock errors while reading salt.
type ErrReader struct{}

func (ErrReader) Read([]byte) (int, error) {
	return 0, io.ErrClosedPipe
}
