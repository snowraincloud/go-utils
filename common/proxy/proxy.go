package proxy

import (
	"net/http"
	"time"
)

type IProxy interface {
	ServeHTTP(http.ResponseWriter, *http.Request)
}

func NewDefaultProxyServer(addr string, proxy IProxy) (*http.Server, error) {

	server := &http.Server{
		Addr:         addr,
		Handler:      proxy,
		ReadTimeout:  1 * time.Minute,
		WriteTimeout: 1 * time.Minute,
	}

	return server, nil
}
