// +build go1.11

package passwd

import (
	"fmt"
	"testing"
)

//
//
// TestVectors
//
//
/*
var vectorNewTests = []struct {
	pro HashProfile,
	err error,
}{
	{ Argon2idDefault, nil },
	{ Argon2idDefault, nil },
	{ Argon2idDefault, nil },
	{ Argon2idDefault, nil },
}
*/

var vectorNewTests = []struct {
	profile  HashProfile
	expected error
}{
	{Argon2idDefault, nil},
	{Argon2idParanoid, nil},
	{ScryptDefault, nil},
	{ScryptParanoid, nil},
	{BcryptDefault, nil},
	{BcryptParanoid, nil},
	{Argon2Custom, ErrUnsupported},
	{ScryptCustom, ErrUnsupported},
	{BcryptCustom, ErrUnsupported},
}

//
//
// TestFunction
//
//
func TestNew(t *testing.T) {
	for i, test := range vectorNewTests {
		myprofile, err := New(test.profile)
		if err != test.expected {
			t.Fatalf("test #%d: profile: %d err: %v vs expected: %v\n", i, myprofile, err, test.expected)
		}
	}
}

func TestNewMasked(t *testing.T) {
	for i, test := range vectorNewTests {
		myprofile, err := NewMasked(test.profile)
		if err != test.expected {
			t.Fatalf("test #%d: profile: %d err: %v vs expected: %v\n", i, myprofile, err, test.expected)
		}
	}
}

//
//
// Examples for documentation
//
//

func ExampleNew() {
	p, err := New(Argon2idDefault)
	if err != nil {
		panic(err)
	}

	_, err = p.Hash([]byte("mylamepass!!"))
	if err != nil {
		panic(err)
	}
	fmt.Printf("argon hashed")
	// Output: argon hashed
}

func ExampleNewMasked() {
	p, err := NewMasked(Argon2idDefault)
	if err != nil {
		panic(err)
	}
	_, err = p.Hash([]byte("mylamepass!!"))
	if err != nil {
		panic(err)
	}
	fmt.Printf("argon hashed")
	// Output: argon hashed
}

func ExampleCompare() {
	hashedPassword := []byte("$2id$aiOE.rPFUFkkehxc6utWY.$1$65536$8$32$Wv1IMP6xwaqVaQGOX6Oxe.eSEbozeRJLzln8ZlthZfS")
	err := Compare(hashedPassword, []byte("prout"))
	if err != nil {
		fmt.Printf("err: %v\n", err)
	}
	fmt.Printf("compared")
	// Output: compared
}

func ExampleProfile_Compare() {
	hashedPassword := []byte("$2id$PEKC7uef8j09Tx8WHKrpwu$e1ZINFSkJz4/hM0mytQCjrEmVRRb6VtkXwAZibZhgYm")
	p, err := NewMasked(Argon2idDefault)
	if err != nil {
		panic(err)
	}
	err = p.Compare(hashedPassword, []byte("prout"))
	if err != nil {
		//panic(err)
		fmt.Printf("err: %v\n", err)
	}
	fmt.Printf("compared")
	// Output: compared
}
