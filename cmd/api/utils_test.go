package main

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestGetExpiry(t *testing.T) {
	Convey("given a data string", t, func() {
		data := []byte("meme                      0x2add4c4b1f559973fef06acb253694d9d (valid until 2022-06-09 12:40:48 +0000 UTC)")

		Convey("when getting the expiry", func() {
			a, b, c, err := getExpiry(data, nil)
			So(err, ShouldBeNil)

			Convey("it should have the fingerprint", func() {
				So(a, ShouldEqual, "meme")
			})

			Convey("it should have the cn", func() {
				So(b, ShouldEqual, "0x2add4c4b1f559973fef06acb253694d9d")
			})

			Convey("it should have the validity date", func() {
				So(c, ShouldEqual, "2022-06-09T12:40:48Z")
			})
		})
	})
}
