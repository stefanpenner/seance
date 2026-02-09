//go:build !no_editor && darwin && arm64

package editor

import _ "embed"

//go:embed code-server.tar.gz
var codeServerArchive []byte
