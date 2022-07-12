package proxy

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"hash/fnv"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	pkgerr "github.com/pkg/errors"
	"github.com/snowraincloud/go-utils/common"
)

type ICertManagement interface {
	GetCert(string) (*tls.Certificate, error)
	AddCert(string, *tls.Certificate) error
}

var (
	defaultRootCaPem = []byte(`
-----BEGIN CERTIFICATE-----
MIICBTCCAaqgAwIBAgIBATAKBggqhkjOPQQDAjBaMQ4wDAYDVQQGEwVDaGluYTEO
MAwGA1UECBMFSHViZWkxDjAMBgNVBAcTBVd1aGFuMRAwDgYDVQQKEwdGb3J3YXJk
MRYwFAYDVQQDDA1odHRwc19mb3J3YXJkMB4XDTIxMDYyNDA4MDAwOVoXDTQyMDYy
NDA4MDAwOVowWjEOMAwGA1UEBhMFQ2hpbmExDjAMBgNVBAgTBUh1YmVpMQ4wDAYD
VQQHEwVXdWhhbjEQMA4GA1UEChMHRm9yd2FyZDEWMBQGA1UEAwwNaHR0cHNfZm9y
d2FyZDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPFLTsXmrzLUSG4/B+Q2KXjt
2mfsoFO6j0b/QHzNTgZVpUUbmaWOAme4H/04IFJNBF2m7DDu3i/DYNUnTKq8Kkqj
YTBfMA4GA1UdDwEB/wQEAwIBBjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUH
AwEwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUYydnnTxNzOTfHCrYBXIbLNtu
L9AwCgYIKoZIzj0EAwIDSQAwRgIhAKERFge+CagR612vwYqhve56ygcu7lQ70IVU
QRLFAIZvAiEAvEyNzS8TQsH/uHFBL8rKc4Aa0gzWfR+AdjeupJKpXNo=
-----END CERTIFICATE-----
`)

	defaultRootKeyPem = []byte(`
-----BEGIN EC PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg7cPbPqTj7OtURNYe
m74YVgMh4hqNeO6lXTeQIInKeAyhRANCAATxS07F5q8y1EhuPwfkNil47dpn7KBT
uo9G/0B8zU4GVaVFG5mljgJnuB/9OCBSTQRdpuww7t4vw2DVJ0yqvCpK
-----END EC PRIVATE KEY-----
`)
)

type MyRootCa struct {
	Ca    *x509.Certificate
	Bytes *[]byte
}

type MyRootKey struct {
	Key   crypto.Signer
	Bytes *[]byte
}

type DefaultCertManagement struct {
	rootCA  *MyRootCa
	rootKey *MyRootKey
	certs   sync.Map
}

type options struct {
	rootCa  *[]byte
	rootKey *[]byte
}

type Option func(opt *options)

func WithRootCa(rootCa *[]byte) Option {
	return func(opt *options) {
		opt.rootCa = rootCa
	}
}

func WithRootKey(rootKey *[]byte) Option {
	return func(opt *options) {
		opt.rootKey = rootKey
	}
}

func NewDefaultCertManagementFromFile(ca, key string) (*DefaultCertManagement, error) {
	caContent, err := os.ReadFile(ca)
	if err != nil {
		return nil, pkgerr.Wrap(err, "Failed to load ca file")
	}
	keyContent, err := os.ReadFile(key)
	if err != nil {
		return nil, pkgerr.Wrap(err, "Failed to load key file")
	}
	certManagement, err := NewDefaultCertManagement(WithRootCa(&caContent), WithRootKey(&keyContent))
	return certManagement, err
}

func NewDefaultCertManagement(modifyOpts ...Option) (*DefaultCertManagement, error) {
	// default config
	opts := options{
		rootCa:  &defaultRootCaPem,
		rootKey: &defaultRootKeyPem,
	}
	// load custom config
	for _, modify := range modifyOpts {
		modify(&opts)
	}
	// load root certificate
	block, _ := pem.Decode(*opts.rootCa)
	rootCA, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, pkgerr.Wrap(err, "Load root certificate failure")
	}
	// load root privare key
	block, _ = pem.Decode(*opts.rootKey)
	rootKey, err := parsePrivateKey(block.Bytes)
	if err != nil {
		return nil, pkgerr.Wrap(err, "Load root private key failure")
	}
	// initialization the default certificate manager
	certManagement := &DefaultCertManagement{
		rootCA: &MyRootCa{
			Ca:    rootCA,
			Bytes: opts.rootCa,
		},
		rootKey: &MyRootKey{
			Key:   rootKey,
			Bytes: opts.rootKey,
		},
	}
	return certManagement, nil
}

func OutputDefaultCertAndPrivKey(path string) error {
	ca, _ := pem.Decode(defaultRootCaPem)
	err := save(ca, path+"/defaultCa.crt")
	if err != nil {
		return pkgerr.Wrap(err, "Save default certificate file failure")
	}

	privKey, _ := pem.Decode(defaultRootKeyPem)
	err = save(privKey, path+"/defaultCa.key")
	if err != nil {
		return pkgerr.Wrap(err, "Save default private key file failure")
	}

	return nil
}

func GenerateCertBlock() (*pem.Block, *pem.Block, error) {

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "https_forward",
			Country:      []string{"China"},
			Organization: []string{"Forward"},
			Province:     []string{"Hubei"},
			Locality:     []string{"Wuhan"},
		},
		NotBefore:             time.Now().AddDate(-1, 0, 0),
		NotAfter:              time.Now().AddDate(20, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// pub, priv, err := ed25519.GenerateKey(rand.Reader)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, pkgerr.Wrap(err, "Generate private key failure")
	}
	// create certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, pkgerr.Wrap(err, "Create certificate failure")
	}
	certBlock := &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}
	// convert to byte
	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, pkgerr.Wrap(err, "Marshal private key failure")
	}
	// save private key
	keyBlock := &pem.Block{
		// Type: "	ED25519 PRIVATE KEY",
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	}
	return certBlock, keyBlock, nil
}

func (c *DefaultCertManagement) GetCert(host string) (*tls.Certificate, error) {
	if host == "" {
		return nil, fmt.Errorf("The certificate host cannot be empty")
	}
	// remove port number
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	// load certificate from certificate cache
	v, ok := c.certs.Load(host)
	if !ok {
		// create certificate
		tmpl, err := GenerateTemplate(host, 300)
		if err != nil {
			return nil, pkgerr.Wrap(err, "Gernerate certificate template failure")
		}
		cert, err := GenerateCert(tmpl, c.rootCA.Ca, c.rootKey)
		if err != nil {
			return nil, pkgerr.Wrap(err, "Generate certificate failure")
		}
		// cache certificate
		if len(tmpl.IPAddresses) > 0 {
			c.AddCert(host, cert)
		}
		for _, item := range tmpl.DNSNames {
			item = strings.TrimPrefix(item, "*.")
			c.AddCert(host, cert)
		}
		return cert, nil
	}
	return v.(*tls.Certificate), nil
}

func (c *DefaultCertManagement) AddCert(host string, cert *tls.Certificate) error {
	if host == "" {
		return fmt.Errorf("The certificate host cannot be empty")
	}
	if cert == nil {
		return fmt.Errorf("The certificate cannot be nil")
	}
	c.certs.Store(host, cert)
	return nil
}

func GenerateCert(tmpl *x509.Certificate, rootCA *x509.Certificate, rootKey *MyRootKey) (*tls.Certificate, error) {
	// create certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, tmpl, rootCA, rootKey.Key.Public(), rootKey.Key)
	if err != nil {
		return nil, pkgerr.Wrap(err, "Create certificate failure")
	}
	// convert to pem code
	certBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}
	certPEMBlock := pem.EncodeToMemory(certBlock)
	// convert to x509 certificate
	cert, err := tls.X509KeyPair(certPEMBlock, *rootKey.Bytes)
	if err != nil {
		return nil, pkgerr.Wrap(err, "Create x509 certificate failure")
	}
	return &cert, nil
}

// generate certificate template
func GenerateTemplate(host string, expireDays int) (*x509.Certificate, error) {
	// hash
	fv := fnv.New32a()
	_, err := fv.Write([]byte(host))
	if err != nil {
		return nil, err
	}
	// Generate ceratificate
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(int64(fv.Sum32())),
		Subject: pkix.Name{
			CommonName:   host,
			Country:      []string{"China"},
			Organization: []string{"Forward"},
			Province:     []string{"HuBei"},
			Locality:     []string{"WuHan"},
		},
		NotBefore:             time.Now().AddDate(-1, 0, 0),
		NotAfter:              time.Now().AddDate(0, 0, expireDays),
		BasicConstraintsValid: true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment | x509.KeyUsageKeyEncipherment,
	}
	// Add ip or domain
	hosts := strings.Split(host, ",")
	for _, item := range hosts {
		if ip := net.ParseIP(host); ip != nil {
			cert.IPAddresses = append(cert.IPAddresses, ip)
			continue
		}

		fields := strings.Split(item, ".")
		fieldNum := len(fields)
		for i := 0; i <= (fieldNum - 2); i++ {
			cert.DNSNames = append(cert.DNSNames, "*."+strings.Join(fields[i:], "."))
		}
		if fieldNum == 2 {
			cert.DNSNames = append(cert.DNSNames, item)
		}
	}
	return cert, nil
}

func save(data *pem.Block, path string) error {
	return common.Save(pem.EncodeToMemory(data), path)
}

// parse pem encode private key
func parsePrivateKey(der []byte) (crypto.Signer, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
			return key.(crypto.Signer), nil
		default:
			return nil, errors.New("tls: found unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, errors.New("tls: failed to parse private key")
}
