// askpass.go -- Interactive password prompt
//
// (c) 2016 Sudhi Herle <sudhi@herle.net>
//
// Placed in the Public Domain
//
// This software does not come with any express or implied
// warranty; it is provided "as is". No claim  is made to its
// suitability for any purpose.
package utils

import (
	"fmt"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"
)

// Askpass prompts user for an interactive password.
// If verify is true, confirm a second time.
// Mistakes during confirmation cause the process to restart upto a
// maximum of 2 times.
func Askpass(prompt string, verify bool) (string, error) {

	for i := 0; i < 2; i++ {
		fmt.Printf("%s: ", prompt)
		pw1, err := terminal.ReadPassword(int(syscall.Stdin))
		fmt.Printf("\n")
		if err != nil {
			return "", err
		}
		if !verify {
			return string(pw1), nil
		}

		fmt.Printf("%s again: ", prompt)
		pw2, err := terminal.ReadPassword(int(syscall.Stdin))
		fmt.Printf("\n")
		if err != nil {
			return "", err
		}

		a := string(pw1)
		b := string(pw2)
		if a == b {
			return a, nil
		}

		fmt.Printf("** password mismatch; try again ..\n")
	}

	return "", fmt.Errorf("Too many tries getting password")
}
// vim: ft=go:sw=8:ts=8:noexpandtab:tw=98:
