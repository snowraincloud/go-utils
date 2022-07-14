package win

import (
	"os/exec"
	"strings"
)

func OpenExplorer(path string) error {
	path = strings.ReplaceAll(path, "/", "\\")
	return exec.Command(`cmd`, `/c`, `explorer`, path).Start()
}

func OpenBrowser(uri string) error {
	return exec.Command(`cmd`, `/c`, `start`, uri).Start()
}
