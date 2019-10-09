// opts.go - multivalued command line options
//
// Implements the Value interface in github.com/opencoff/pflag
//
// (c) 2018 Sudhi Herle; License GPLv2
//
// This software does not come with any express or implied
// warranty; it is provided "as is". No claim  is made to its
// suitability for any purpose.

package main

import (
	"fmt"
	"strings"

	"github.com/opencoff/pflag"
)

var (
	_ pflag.Value = &StringList{}
)


type StringList struct {
	V []string
}

func (i *StringList) Set(s string) error {
	v := strings.Split(s, ",")
	i.V = append(i.V, v...)
	return nil
}

func (i *StringList) String() string {
	z := strings.Join(i.V, ",")
	return fmt.Sprintf("[%s]", z)
}
