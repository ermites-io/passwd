// +build go1.11

package passwd

import (
	"fmt"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

//
//
// TestVectors
//
//
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
	profile         HashProfile
	passwordHash    string
	passwordCompare string
	expectedHash    error
	expectedCompare error
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

var vectorNewCustomTest = []struct {
	params            interface{}
	profileEqual      HashProfile
	passwordToHash    string
	expectedNewCustom error
	expectedHash      error
	expectedCompare   error
}{
	{Argon2Params{ // Argon2idDefault aka MATCHING CONDITIONS
		Version: Argon2id,
		Time:    1,
		Memory:  64 * 1024,
		Thread:  16,
		Saltlen: 16,
		Keylen:  32,
		Masked:  true,
	}, Argon2idDefault, "testpassword", nil, nil, nil},
	{Argon2Params{ // NON MATCHING
		Version: Argon2id,
		Time:    1,
		Memory:  64 * 1024,
		Thread:  16,
		Saltlen: 32, // non matching param
		Keylen:  32,
		Masked:  true,
	}, Argon2idDefault, "testpassword", nil, nil, ErrMismatch},
	{Argon2Params{ // NON MATCHING
		Version: Argon2id,
		Time:    1,
		Memory:  64 * 1024,
		Thread:  16,
		Saltlen: 16,
		Keylen:  16, // non matching param
		Masked:  true,
	}, Argon2idDefault, "testpassword", nil, nil, ErrMismatch},
	{Argon2Params{ // NON MATCHING
		Version: Argon2id,
		Time:    1,
		Memory:  64 * 1024,
		Thread:  8, // non matching param
		Saltlen: 16,
		Keylen:  32,
		Masked:  true,
	}, Argon2idDefault, "testpassword", nil, nil, ErrMismatch},
	{Argon2Params{ // NON MATCHING
		Version: Argon2id,
		Time:    1,
		Memory:  32 * 1024, // non matching param
		Thread:  16,
		Saltlen: 16,
		Keylen:  32,
		Masked:  true,
	}, Argon2idDefault, "testpassword", nil, nil, ErrMismatch},
	{ScryptParams{ // ScryptDefault aka MATCHING CONDITION
		N:       1 << 16,
		R:       8,
		P:       1,
		Saltlen: 16,
		Keylen:  32,
		Masked:  true,
	}, ScryptDefault, "testpassword", nil, nil, nil},
	{ScryptParams{ // NON MATCHING
		N:       1 << 16,
		R:       8,
		P:       1,
		Saltlen: 10, // non matching param
		Keylen:  32,
		Masked:  true,
	}, ScryptDefault, "testpassword", nil, nil, ErrMismatch},
	{ScryptParams{ // NON MATCHING
		N:       1 << 16,
		R:       8,
		P:       1,
		Saltlen: 16,
		Keylen:  16, // non matching param
		Masked:  true,
	}, ScryptDefault, "testpassword", nil, nil, ErrMismatch},
	{ScryptParams{ // NON MATCHING
		N:       1 << 16,
		R:       4, // non matching param
		P:       1,
		Saltlen: 16,
		Keylen:  32,
		Masked:  true,
	}, ScryptDefault, "testpassword", nil, nil, ErrMismatch},
	{ScryptParams{ // NON MATCHING
		N:       1 << 14, // non matching param
		R:       8,
		P:       1,
		Saltlen: 16,
		Keylen:  32,
		Masked:  true,
	}, ScryptDefault, "testpassword", nil, nil, ErrMismatch},
	{BcryptParams{
		Cost: bcrypt.DefaultCost,
	}, BcryptDefault, "testpassword", nil, nil, nil},
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

func TestNewCustom(t *testing.T) {
	for i, test := range vectorNewCustomTest {
		myprofileCustom, err := NewCustom(test.params)
		if err != test.expectedNewCustom {
			t.Fatalf("test #%d: profile: %v err: %v vs expected: %v\n", i, test.params, err, test.expectedNewCustom)
		}

		myprofileOrig, err := NewMasked(test.profileEqual)
		if err != nil {
			t.Fatalf("test #%d: profile: %d err: %v vs expected: %v\n", i, test.profileEqual, err, test.expectedNewCustom)
		}

		hashCustom, err := myprofileCustom.Hash([]byte(test.passwordToHash))
		if err != test.expectedHash {
			t.Fatalf("test #%d (hash): profile: %v err: %v vs expected: %v\n", i, test.params, err, test.expectedHash)
		}

		hashOrig, err := myprofileOrig.Hash([]byte(test.passwordToHash))
		if err != test.expectedHash {
			t.Fatalf("test #%d (hash): profile: %d err: %v vs expected: %v\n", i, test.profileEqual, err, test.expectedHash)
		}

		// we share the params so it should match
		err = myprofileOrig.Compare(hashCustom, []byte(test.passwordToHash))
		if err != test.expectedCompare {
			t.Fatalf("test #%d (passwd.Compare): profile: %v err: %v vs expected: %v\n", i, test.params, err, test.expectedCompare)
		}

		err = myprofileCustom.Compare(hashOrig, []byte(test.passwordToHash))
		if err != test.expectedCompare {
			t.Fatalf("test #%d (passwd.Compare): profile: %d err: %v vs expected: %v\n", i, test.profileEqual, err, test.expectedCompare)
		}
	}
}

func TestHashCompare(t *testing.T) {
	for i, test := range vectorHashCompareTests {
		myprofile, err := New(test.profile)
		if err != nil {
			t.Fatalf("could not New() on #%d\n", i)
		}
		hash, err := myprofile.Hash([]byte(test.passwordHash))
		if err != test.expectedHash {
			t.Fatalf("test #%d (hash): profile: %d err: %v vs expected: %v\n", i, myprofile, err, test.expectedHash)
		}

		err = Compare(hash, []byte(test.passwordCompare))
		if err != test.expectedCompare {
			t.Fatalf("test #%d (Compare): profile: %d err: %v vs expected: %v\n", i, myprofile, err, test.expectedCompare)
		}

		err = myprofile.Compare(hash, []byte(test.passwordCompare))
		if err != test.expectedCompare {
			t.Fatalf("test #%d (passwd.Compare): profile: %d err: %v vs expected: %v\n", i, myprofile, err, test.expectedCompare)
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
