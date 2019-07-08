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

var vectorHashCompareTests = []struct {
	profile          HashProfile
	password_hash    string
	password_compare string
	expected_hash    error
	expected_compare error
}{
	// argon
	{Argon2idDefault, "1", "1", nil, nil},
	{Argon2idDefault, "12", "12", nil, nil},
	{Argon2idDefault, "123456789012345678901234567890", "123456789012345678901234567890", nil, nil},
	{Argon2idDefault, "123456789012345678901234567890", "1234567890123456789012345678901", nil, ErrMismatch},
	{Argon2idDefault, "12345678901234567890123456789", "123456789012345678901234567890", nil, ErrMismatch},

	// scrypt
	{ScryptDefault, "1", "1", nil, nil},
	{ScryptDefault, "12", "12", nil, nil},
	{ScryptDefault, "123456789012345678901234567890", "123456789012345678901234567890", nil, nil},
	{ScryptDefault, "123456789012345678901234567890", "1234567890123456789012345678901", nil, ErrMismatch},
	{ScryptDefault, "12345678901234567890123456789", "123456789012345678901234567890", nil, ErrMismatch},

	// bcrypt
	{BcryptDefault, "1", "1", nil, nil},
	{BcryptDefault, "12", "12", nil, nil},
	{BcryptDefault, "123456789012345678901234567890", "123456789012345678901234567890", nil, nil},
	{BcryptDefault, "123456789012345678901234567890", "1234567890123456789012345678901", nil, ErrMismatch},
	{BcryptDefault, "12345678901234567890123456789", "123456789012345678901234567890", nil, ErrMismatch},
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

func TestHashCompare(t *testing.T) {
	for i, test := range vectorHashCompareTests {
		myprofile, err := New(test.profile)
		if err != nil {
			t.Fatalf("could not New() on #%d\n", i)
		}
		hash, err := myprofile.Hash([]byte(test.password_hash))
		if err != test.expected_hash {
			t.Fatalf("test #%d (hash): profile: %d err: %v vs expected: %v\n", i, myprofile, err, test.expected_hash)
		}

		err = Compare(hash, []byte(test.password_compare))
		if err != test.expected_compare {
			t.Fatalf("test #%d (Compare): profile: %d err: %v vs expected: %v\n", i, myprofile, err, test.expected_compare)
		}

		err = myprofile.Compare(hash, []byte(test.password_compare))
		if err != test.expected_compare {
			t.Fatalf("test #%d (passwd.Compare): profile: %d err: %v vs expected: %v\n", i, myprofile, err, test.expected_compare)
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
