// +build go1.11

package passwd

import (
	"fmt"
)

func ExampleNew() {
	p := New(Argon2idDefault)
	h, err := p.Hash([]byte("mylamepass!!"))
	if err != nil {
		panic(err)
	}
	fmt.Printf("hashed('mylamepass!!'): %s\n", h)
	// Output:
	// hashed('mylamepass!!'): $2id$params$*password_hash*
}

func ExampleNewMasked() {
	p := NewMasked(Argon2idDefault)
	h, err := p.Hash([]byte("mylamepass!!"))
	if err != nil {
		panic(err)
	}
	fmt.Printf("hashed('mylamepass!!'): %s\n", h)
}

func ExampleCompare() {
	hashedPassword := "$2id$aiOE.rPFUFkkehxc6utWY.$1$65536$8$32$Wv1IMP6xwaqVaQGOX6Oxe.eSEbozeRJLzln8ZlthZfS"
	err := Compare(hashedpassword, []byte("prout"))
	fmt.Printf("Compare err: %v", err)
}

func ExampleProfile_Compare() {
	hashedPassword := "$2id$PEKC7uef8j09Tx8WHKrpwu$e1ZINFSkJz4/hM0mytQCjrEmVRRb6VtkXwAZibZhgYm"
	p := NewMasked(Argon2idDefault)
	err := p.Compare(hashedpassword, []byte("prout"))
	fmt.Printf("Masked Compare err: %v", err)
}
