//go:build !(darwin || linux) || !(amd64 || arm64)

package editor

var codeServerArchive []byte
