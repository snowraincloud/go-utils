package registry

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestStystemProxy(t *testing.T) {
	Convey("Test for system proxy", t, func() {

		addr := "127.0.0.1:8888"
		err := StartSystemProxy(addr)
		So(err, ShouldBeNil)

		status, err := GetSystemProxyStatus()
		So(err, ShouldBeNil)
		So(status, ShouldNotBeNil)
		So(status.Enable, ShouldBeTrue)
		So(status.Address, ShouldEqual, addr)

		err = StopSystemProxy()
		So(err, ShouldBeNil)

		status, err = GetSystemProxyStatus()
		So(err, ShouldBeNil)
		So(status, ShouldNotBeNil)
		So(status.Enable, ShouldBeFalse)
		So(status.Address, ShouldEqual, addr)

	})
}
