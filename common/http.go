package common

import (
	"fmt"
	"net"
	"net/http"

	pkgerr "github.com/pkg/errors"
)

func Hijack(rw http.ResponseWriter) (net.Conn, error) {
	hijacker, ok := rw.(http.Hijacker)
	if !ok {
		return nil, fmt.Errorf("Hijack http response writer failure")
	}
	conn, _, err := hijacker.Hijack()
	if err != nil {
		return nil, pkgerr.Wrap(err, "Failed to hijack http connect")
	}
	return conn, nil
}
