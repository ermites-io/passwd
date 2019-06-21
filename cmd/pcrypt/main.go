// +build go1.11

package main

import (
	"flag"
	"fmt"
	"os"

	"git.sr.ht/~eau/passwd"
)

// a simple example of passwd package usage.
func main() {
	//var p *passwd.Profile
	var profile passwd.HashProfile

	scryptFlag := flag.Bool("scrypt", false, "use scrypt derivation")
	argonFlag := flag.Bool("argon", false, "use argon derivation")
	bcryptFlag := flag.Bool("bcrypt", false, "use bcrypt derivation")
	checkFlag := flag.String("check", "", "hash to compare")
	maskedFlag := flag.Bool("mask", false, "generate masked hash")

	flag.Parse()
	argv := flag.Args()

	switch {
	case *argonFlag:
		profile = passwd.Argon2idDefault
	case *scryptFlag:
		profile = passwd.ScryptDefault
	case *bcryptFlag:
		profile = passwd.BcryptDefault
	default:
		fmt.Printf("no derivation, so nothing to do")
		os.Exit(0)
	}

	// profile
	// PUBLIC PARAMETERS
	//p := passwd.New(profile)
	//fmt.Printf("argv[%d]: %q\n", len(argv), argv)
	if len(argv) > 0 {
		switch {
		case len(*checkFlag) > 0:
			for idx, passwordStr := range argv {
				fmt.Printf("[%d] is '%s' the passwd? %v\n",
					idx,
					passwordStr,
					passwd.Compare([]byte(*checkFlag), []byte(passwordStr)),
				)
			}
		default:
			for idx, passwordStr := range argv {
				ph, err := passwd.New(profile)
				if *maskedFlag {
					ph, err = passwd.NewMasked(profile)
				}
				if err != nil {
					panic(err)
				}
				h, err := ph.Hash([]byte(passwordStr))
				if err != nil {
					panic(err)
				}
				fmt.Printf("[%d] password: '%s' hashed: '%s'\n", idx, passwordStr, h)
			}
		}
	}

	// MASKED PARAMETERS
	/*
		p := passwd.NewMasked(profile)
		fmt.Printf("argv[%d]: %q\n", len(argv), argv)
		if len(argv) > 0 {
			for idx, passwordStr := range argv {
				h, err := p.Hash([]byte(passwordStr))
				if err != nil {
					log.Fatalf("hashing error: %v\n", err)
				}
				fmt.Printf("[%d] password: '%s' hashed: '%s'\n", idx, passwordStr, h)
				if len(*checkFlag) > 0 {
					fmt.Printf("[%d] is '%s' the passwd? %v\n",
						idx, passwordStr,
						p.Compare([]byte(*checkFlag), []byte(passwordStr)))
				}
			}
		}
	*/

	os.Exit(0)
}
