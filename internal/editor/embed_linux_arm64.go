//go:build !no_editor && linux && arm64

package editor

import _ "embed"

//go:embed code-server.tar.gz
var codeServerArchive []byte
