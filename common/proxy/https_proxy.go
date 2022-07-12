package proxy

import (
	"io"
	"net"
	"net/http"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/snowraincloud/go-utils/common"
)

var TunnelEstablishedResponseLine = []byte("HTTP/1.1 200 Connection established\r\n\r\n")

type DefaultHttpsProxy struct {
	rules []IRule
}

func NewDefaultHttpsProxy(rules []IRule) (*DefaultHttpsProxy, error) {
	httpsProxy := &DefaultHttpsProxy{
		rules: rules,
	}
	return httpsProxy, nil
}

func (p *DefaultHttpsProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	for _, rule := range p.rules {
		res, err := rule.Match(req)
		if err != nil {
			log.Infof("Execute proxy match failure : req [%v]", req)
			continue
		}
		if res {
			err = rule.Handle(rw, req)
			if err != nil {
				log.Infof("Execute proxy handler failure : req [%v]", req)
				continue
			}
			return
		}
	}
	// hijack http connection
	conn, err := common.Hijack(rw)
	if err != nil {
		log.Infof("Http request hijack failure: %s", err)
		return
	}

	if !strings.HasSuffix(req.Host, ":443") {
		req.Host += ":443"
	}
	server, err := net.Dial("tcp", req.Host)
	if err != nil {
		log.Tracef("[%s]: [%s]", err, req.Host)
		return
	}

	if req.Method == "CONNECT" {
		// write http connect response
		_, err = conn.Write(TunnelEstablishedResponseLine)
		if err != nil {
			log.Infof("Failed to resonse http connect: %s", err)
		}
	}
	// request forward
	go io.Copy(server, conn)
	go io.Copy(conn, server)
}
