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
