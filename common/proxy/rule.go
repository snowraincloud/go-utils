package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"

	pkgerr "github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/snowraincloud/go-utils/common"
	"github.com/spf13/viper"
	"github.com/viki-org/dnscache"
)

type IRule interface {
	Match(*http.Request) (bool, error)
	Handle(http.ResponseWriter, *http.Request) error
}

type RuleConfig struct {
	ForwardRules []ForwardRuleConfig `yaml:"forwardRules"`
}

type ForwardRuleConfig struct {
	Name       string `yaml:"name"`
	MatchPath  string `yaml:"matchPath"`
	TargetPath string `yaml:"targetPath"`
}

type ForwardRule struct {
	rules          map[string]ForwardRuleConfig
	certManagement ICertManagement
	transport      *http.Transport
}

func OutPutRuleExample() error {
	path := "./out/rule-sample.yml"

	rules := `forwardRules:
  - name: example
    matchPath: example.com/app
    targetPath: http://localhost/app
`
	return common.Save([]byte(rules), path)
}

func NewForwardRuleFromConf(certManagement ICertManagement, fileName string) (*ForwardRule, error) {
	viper.SetConfigType("yml")
	viper.SetConfigFile(fileName)

	err := viper.ReadInConfig()
	if err != nil {
		return nil, pkgerr.Wrap(err, "Open rule config file failure")
	}
	conf := &RuleConfig{}
	err = viper.Unmarshal(&conf)
	if err != nil {
		return nil, pkgerr.Wrap(err, "Failed to unmarshal rule config file")
	}
	log.Infof("Load rule config file from [%s]", fileName)
	return NewForwardRule(certManagement, conf.ForwardRules...)
}

func NewForwardRule(certManagement ICertManagement, rules ...ForwardRuleConfig) (*ForwardRule, error) {
	// if len(rules) == 0 {
	// 	return nil, fmt.Errorf("Forward rule config must not null")
	// }
	dnsCache := dnscache.New(5 * time.Minute)
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		MaxIdleConns:          100,
		MaxConnsPerHost:       10,
		IdleConnTimeout:       10 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{
				Timeout: 5 * time.Second,
			}
			separator := strings.LastIndex(addr, ":")
			ips, err := dnsCache.Fetch(addr[:separator])
			if err != nil {
				return nil, err
			}
			var ip string
			for _, item := range ips {
				ip = item.String()
				if !strings.Contains(ip, ":") {
					break
				}
			}

			addr = ip + addr[separator:]

			return dialer.DialContext(ctx, network, addr)
		},
	}
	rulesMap := make(map[string]ForwardRuleConfig)
	for _, rule := range rules {
		domain := strings.Split(rule.MatchPath, "/")[0]
		rulesMap[domain] = rule
	}

	r := &ForwardRule{
		rules:          rulesMap,
		certManagement: certManagement,
		transport:      transport,
	}
	return r, nil
}

func (r *ForwardRule) Match(req *http.Request) (bool, error) {
	path := req.Host[:len(req.Host)-4]
	_, ok := r.rules[path]
	return ok, nil
}

func (r *ForwardRule) Handle(rw http.ResponseWriter, req *http.Request) error {
	// get connection
	conn, err := common.Hijack(rw)
	if err != nil {
		return pkgerr.Wrap(err, "Http request hijack failure")
	}
	defer func() {
		_ = conn.Close()
	}()
	// write http connect response
	_, err = conn.Write(TunnelEstablishedResponseLine)
	if err != nil {
		return pkgerr.Wrap(err, "Failed to resonse http connect")
	}
	// get certificate
	cert, err := r.certManagement.GetCert(req.URL.Host)
	if err != nil {
		return pkgerr.Wrap(err, "Failed to get certificate")
	}
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{*cert},
	}
	// tls connection
	tlsClientConn := tls.Server(conn, tlsConf)
	defer func() {
		_ = tlsClientConn.Close()
	}()
	// tls handshake
	if err := tlsClientConn.Handshake(); err != nil {
		return fmt.Errorf("Tls handshake failure: [%s], [%s]", req.URL.Host, err)
	}
	// parse http request
	buf := bufio.NewReader(tlsClientConn)
	tlsReq, err := http.ReadRequest(buf)
	if err != nil {
		if err != io.EOF {
			err = fmt.Errorf("Tls read client request failure: [%s], [%s]", req.URL.Host, err)
		}
		return err
	}
	// build forward http request
	path := tlsReq.Host + tlsReq.URL.Path
	forwardRulePath, _ := r.rules[tlsReq.Host]
	log.Tracef("Forward rule : request path [%s]", path)

	if strings.HasPrefix(path, forwardRulePath.MatchPath) {
		targetPath := forwardRulePath.TargetPath + path[len(forwardRulePath.MatchPath):]
		log.Infof("https forward : source path [%s], target path: [%s]", path, targetPath)
		// transmit request header and body
		body, err := ioutil.ReadAll(tlsReq.Body)
		if err != nil {
			return fmt.Errorf("Failed to read http request body: [%s]", err)
		}
		req, _ = http.NewRequest(tlsReq.Method, targetPath, nil)
		req.Body = ioutil.NopCloser(bytes.NewReader(body))
		req.Header["Content-Type"] = tlsReq.Header["Content-Type"]
	} else {
		tlsReq.RemoteAddr = req.RemoteAddr
		tlsReq.URL.Scheme = "https"
		tlsReq.URL.Host = tlsReq.Host
		req = tlsReq

	}
	// forward
	resp, err := r.transport.RoundTrip(req)
	err = resp.Write(tlsClientConn)
	if err != nil {
		return fmt.Errorf("Encryption return value failure: [%s], [%s]", req.URL.Host, err)
	}
	err = resp.Body.Close()
	if err != nil {
		return fmt.Errorf("Close http response failure: [%s], [%s]", req.URL.Host, err)
	}
	return nil
}
