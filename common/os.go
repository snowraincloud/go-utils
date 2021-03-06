package common

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"

	pkgerr "github.com/pkg/errors"
)

func SaveToUserHome(data []byte, name string) error {
	userHome, err := Home()
	if err != nil {
		return pkgerr.Wrap(err, "Failed to get user root directory")
	}
	return Save(data, userHome+"/name")
}

func Save(data []byte, path string) error {
	path = strings.ReplaceAll(path, "/", "\\")
	os.MkdirAll(path[:strings.LastIndex(path, "\\")], 666)

	out, err := os.Create(path)
	if err != nil {
		return pkgerr.WithMessagef(err, "Open %s failure", path)
	}

	_, err = out.Write(data)
	if err != nil {
		return pkgerr.WithMessagef(err, "Save %s file failure", path)
	}
	defer out.Close()
	return nil
}

func Home() (string, error) {
	user, err := user.Current()
	if nil == err {
		return user.HomeDir, nil
	}

	// cross compile support

	if "windows" == runtime.GOOS {
		return homeWindows()
	}

	// Unix-like system, so just assume Unix
	return homeUnix()
}

func homeUnix() (string, error) {
	// First prefer the HOME environmental variable
	if home := os.Getenv("HOME"); home != "" {
		return home, nil
	}

	// If that fails, try the shell
	var stdout bytes.Buffer
	cmd := exec.Command("sh", "-c", "eval echo ~$USER")
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return "", err
	}

	result := strings.TrimSpace(stdout.String())
	if result == "" {
		return "", errors.New("blank output when reading home directory")
	}

	return result, nil
}

func homeWindows() (string, error) {
	drive := os.Getenv("HOMEDRIVE")
	path := os.Getenv("HOMEPATH")
	home := drive + path

	if drive == "" || path == "" {
		home = os.Getenv("USERPROFILE")
	}
	if home == "" {
		return "", errors.New("HOMEDRIVE, HOMEPATH, and USERPROFILE are blank")
	}

	return home, nil
}
