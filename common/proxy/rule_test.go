package proxy

import (
	"net/http"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestForwardMatch(t *testing.T) {
	certManagement, _ := NewDefaultCertManagement()
	rule := &ForwardRuleConfig{
		MatchPath:  "fat2.com",
		TargetPath: "http://localhost/",
	}
	forwardRule, _ := NewForwardRule(certManagement, *rule)
	Convey("Test for forward rule match", t, func() {
		Convey("match true", func() {
			req, _ := http.NewRequest("GET", "http://fat2.com", nil)
			res, err := forwardRule.Match(req)
			So(err, ShouldBeNil)
			So(res, ShouldBeTrue)
		})

		Convey("match false", func() {
			req, _ := http.NewRequest("GET", "http://1fat2.com", nil)
			res, err := forwardRule.Match(req)
			So(err, ShouldBeNil)
			So(res, ShouldBeFalse)
		})
	})
}
