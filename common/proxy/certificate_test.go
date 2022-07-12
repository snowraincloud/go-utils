package proxy

import (
	"net"
	"strings"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

var certManagement *DefaultCertManagement

func TestOutput(t *testing.T) {
	Convey("Test for output default config ca", t, func() {
		err := OutputDefaultCertAndPrivKey("./out")
		So(err, ShouldBeNil)
	})
}

func TestGererateTemplate(t *testing.T) {
	Convey("Test generate template", t, func() {

		Convey("Host is ip addresss", func() {
			cert, err := GenerateTemplate("127.0.0.1", 100)
			So(err, ShouldBeNil)
			So(len(cert.IPAddresses), ShouldEqual, 1)
		})

		Convey("Host is domain", func() {
			cert, err := GenerateTemplate("oa-fat02.wsecar.com", 100)
			So(err, ShouldBeNil)
			So(len(cert.DNSNames), ShouldEqual, 2)
		})
	})
}

func TestCert(t *testing.T) {
	Convey("Test certificate management", t, func() {
		Convey("Test get certificate", func() {
			cert, err := certManagement.GetCert("")
			So(err, ShouldNotBeNil)
			So(cert, ShouldBeNil)

			cert, err = certManagement.GetCert("127.0.0.1")
			So(err, ShouldBeNil)
			So(cert, ShouldNotBeNil)
		})

		Convey("Test add certificate", func() {
			cert, err := certManagement.GetCert("127.0.0.1")
			So(err, ShouldBeNil)
			So(cert, ShouldNotBeNil)
			err = certManagement.AddCert("127.0.0.1", cert)
			So(err, ShouldBeNil)
		})
	})
}

func TestSplitHost(t *testing.T) {
	Convey("Host split", t, func() {

		Convey("Host is ip addresss", func() {
			host := "127.0.0.1"
			So(net.ParseIP(host), ShouldNotBeNil)
		})

		Convey("Host is domain", func() {
			host := "oa-fat02.wsecar.com"
			fileds := strings.Split(host, ".")
			So(len(fileds), ShouldEqual, 3)
			So(strings.Join(fileds[0:], "."), ShouldEqual, host)
		})
	})
}
