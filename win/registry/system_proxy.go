package registry

import (
	"bytes"
	"encoding/binary"

	"golang.org/x/sys/windows/registry"

	pkgerr "github.com/pkg/errors"
)

type SystemProxyStatus struct {
	Enable  bool
	Address string
}

func StartSystemProxy(server string) error {
	return setProxyForWin(1, server)
}

func StopSystemProxy() error {
	return setProxyForWin(0, "")
}

func GetSystemProxyStatus() (*SystemProxyStatus, error) {
	key, _, err := registry.CreateKey(registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.ALL_ACCESS)
	if err != nil {
		return nil, pkgerr.Wrap(err, "Failed to open registry")
	}
	defer key.Close()

	enable, _, err := key.GetIntegerValue("ProxyEnable")
	if err != nil {
		return nil, pkgerr.Wrap(err, "Failed to get value of proxy enable")
	}

	addr, _, err := key.GetStringValue("ProxyServer")
	if err != nil {
		return nil, pkgerr.Wrap(err, "Failed to get value of proxy address")
	}

	return &SystemProxyStatus{
		Enable:  enable == 1,
		Address: addr,
	}, nil
}

func setProxyForWin(enable uint32, server string) error {
	key, _, err := registry.CreateKey(registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.ALL_ACCESS)
	if err != nil {
		return err
	}

	err = key.SetDWordValue("ProxyEnable", enable)
	if err != nil {
		return pkgerr.Wrap(err, "Failed to set system proxy enable statue")
	}

	if enable == 1 {
		err = key.SetStringValue("ProxyServer", server)
		if err != nil {
			return pkgerr.Wrap(err, "Failed to set proxy address")
		}
	}

	return nil
}

func toBytes(data any) []byte {
	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.BigEndian, data)
	return bytesBuffer.Bytes()
}
