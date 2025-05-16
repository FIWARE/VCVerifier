package common

import "os"

// file system interfaces

type FileAccessor interface {
	ReadFile(filename string) ([]byte, error)
}
type DiskFileAccessor struct{}

func (DiskFileAccessor) ReadFile(filename string) ([]byte, error) {
	return os.ReadFile(filename)
}
