//go:build go1.12
// +build go1.12

package passwd

import (
	"fmt"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// TestVectors
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

var vectorCompatibility = []struct {
	profile HashProfile
	masked  bool
	hash    []byte
	passwd  []byte
	secret  []byte
	want    error
}{
	{ // scrypt all good
		ScryptDefault,
		false,
		[]byte("$2s$sT/eXtwSAJHP6rsglmolxe$65536$8$1$32$LIFT/xDaVv1XcFRLY/XBLjIztaJoK9BLtjFIiLnaXvW"),
		[]byte("prout"),
		nil,
		nil,
	},
	{ // scrypt wrong pass
		ScryptDefault,
		false,
		[]byte("$2s$sT/eXtwSAJHP6rsglmolxe$65536$8$1$32$LIFT/xDaVv1XcFRLY/XBLjIztaJoK9BLtjFIiLnaXvW"),
		[]byte("proutt"),
		nil,
		ErrMismatch,
	},
	{ // scrypt corrupted hash
		ScryptDefault,
		false,
		[]byte("$2s$sT/eXtwSAJHP6rsglmolxe$65536$8$1$32$LIFT/xDaVv1XcFRLY/XBLjIztaJoK9BLtjFIiLnaX"),
		[]byte("prout"),
		nil,
		ErrMismatch,
	},
	{ // scrypt masked hash, but masked disabled (should be enabled to match)
		ScryptDefault,
		false,
		[]byte("$2s$Lh8gOCN2H29b.O4S9BDzNO$zShzcWyU7K6PAVwylCkPF9i7aNpmQ2NB5/O6BqlCI3i"),
		[]byte("prout"),
		nil,
		ErrMismatch,
	},
	{ // scrypt masked hash, but masked disabled (should be enabled to match)
		ScryptDefault,
		true,
		[]byte("$2s$Lh8gOCN2H29b.O4S9BDzNO$zShzcWyU7K6PAVwylCkPF9i7aNpmQ2NB5/O6BqlCI3i"),
		[]byte("prout"),
		nil,
		nil,
	},
	{ // scrypt corrupted hash
		ScryptDefault,
		false,
		[]byte("$2s$sT/eXtwSAJHP6rsglmolxe$65536$8$1$32$LIFT/xDaVv1XcFRLY/XBLjIztaJoK9BLtjFIiLnaXvW         "),
		[]byte("prout"),
		nil,
		ErrMismatch,
	},
	{ // scrypt corrupted hash
		ScryptDefault,
		false,
		[]byte("$2s$sT/eXtwSAJHP6rsglmolxe$65536$8$1$32$LIFT/xDaVv1XcFRLY/XBLjIztaJoK9BLtjFIiLnaXvWGGG"),
		[]byte("prout"),
		nil,
		ErrMismatch,
	},
	{ // bcrypt all good
		BcryptDefault,
		false,
		[]byte("$2a$10$zlKoI5wrYXIa9d186fXI9OAic/y2F5YNyBXpmz5xTpl9hhBAtza6m"),
		[]byte("prout"),
		nil,
		nil,
	},
	{ // bcrypt wrong password
		BcryptDefault,
		false,
		[]byte("$2a$10$zlKoI5wrYXIa9d186fXI9OAic/y2F5YNyBXpmz5xTpl9hhBAtza6m"),
		[]byte("proutt"),
		nil,
		ErrMismatch,
	},
	{ // bcrypt correupted hash
		BcryptDefault,
		false,
		[]byte("$2a$10$zlKoI5wrYXIa9d186fXI9OAic/y2F5YNyBXpmz5xTpl9hhBAtza6n"),
		[]byte("prout"),
		nil,
		ErrMismatch,
	},
	{ // all good
		Argon2idDefault,
		false,
		[]byte("$2id$jHPEXqOJ7PEXodl75xJd.e$1$65536$16$32$xR87mnbB548T4Sj4uSQ0mAjNtIG2D2uG.Aob28QJY2u"), // prout
		[]byte("prout"),
		nil,
		nil,
	},
	{ // invalid password
		Argon2idDefault,
		false,
		[]byte("$2id$jHPEXqOJ7PEXodl75xJd.e$1$65536$16$32$xR87mnbB548T4Sj4uSQ0mAjNtIG2D2uG.Aob28QJY2u"), // prout
		[]byte("pprout"),
		nil,
		ErrMismatch,
	},

	{ // masked and valid
		Argon2idDefault,
		true,
		[]byte("$2id$Ubnnyt80onlzG/5MlokXmu$xvpXX5.3eZBjihHNFEVjLTtURakelLxlkrjBrzv9KA6"), // prout
		[]byte("prout"),
		nil,
		nil,
	},
	{ // masked compare with non masked
		Argon2idDefault,
		false, // invalid
		[]byte("$2id$Ubnnyt80onlzG/5MlokXmu$xvpXX5.3eZBjihHNFEVjLTtURakelLxlkrjBrzv9KA6"), // prout
		[]byte("prout"),
		nil,
		ErrMismatch,
	},
	{ // masked, non-key'd, trying to compare with key'd
		Argon2idDefault,
		true,
		[]byte("$2id$Ubnnyt80onlzG/5MlokXmu$xvpXX5.3eZBjihHNFEVjLTtURakelLxlkrjBrzv9KA6"), // prout
		[]byte("prout"),
		[]byte("secret"), // invalid
		ErrMismatch,
	},
	{ // masked, key'd and valid
		Argon2idDefault,
		true,
		[]byte("$2id$yapnlBLmLVowNBPO.LJhGu$QsWAGb1pNhM2BotmZrKSfuEFGe1bWDtKF9Qz29rCEBq"), // prout
		[]byte("prout"),
		[]byte("secret"),
		nil,
	},
	{ // masked, key'd and valid
		Argon2idDefault,
		true,
		[]byte("$2id$yapnlBLmLVowNBPO.LJhGu$QsWAGb1pNhM2BotmZrKSfuEFGe1bWDtKF9Qz29rCEBq"), // prout
		[]byte("prout"),
		[]byte("ssecret"), // invalid
		ErrMismatch,
	},
	{ // masked, key'd and valid
		Argon2idDefault,
		true,
		[]byte("$2id$yapnlBLmLVowNBPO.LJhGu$QsWAGb1pNhM2BotmZrKSfuEFGe1bWDtKF9Qz29rCEBq"), // prout
		[]byte("pprout"), // invalid
		[]byte("secret"),
		ErrMismatch,
	},
	{ // masked, key'd and valid
		Argon2idDefault,
		false, // invalid
		[]byte("$2id$yapnlBLmLVowNBPO.LJhGu$QsWAGb1pNhM2BotmZrKSfuEFGe1bWDtKF9Qz29rCEBq"), // prout
		[]byte("prout"),
		[]byte("secret"),
		ErrMismatch,
	},
}

var vectorNewMaskedTests = []struct {
	profile  HashProfile
	expected error
}{
	{Argon2idDefault, nil},
	{Argon2idParanoid, nil},
	{ScryptDefault, nil},
	{ScryptParanoid, nil},
	{BcryptDefault, ErrUnsupported},
	{BcryptParanoid, ErrUnsupported},
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
	{&Argon2Params{ // Argon2idDefault aka MATCHING CONDITIONS
		Version: Argon2id,
		Time:    1,
		Memory:  64 * 1024,
		Thread:  16,
		Saltlen: 16,
		Keylen:  32,
		Masked:  true,
	}, Argon2idDefault, "testpassword", nil, nil, nil},
	{&Argon2Params{ // NON MATCHING
		Version: Argon2id,
		Time:    1,
		Memory:  64 * 1024,
		Thread:  16,
		Saltlen: 32, // non matching param
		Keylen:  32,
		Masked:  true,
	}, Argon2idDefault, "testpassword", nil, nil, ErrMismatch},
	{&Argon2Params{ // NON MATCHING
		Version: Argon2id,
		Time:    1,
		Memory:  64 * 1024,
		Thread:  16,
		Saltlen: 16,
		Keylen:  16, // non matching param
		Masked:  true,
	}, Argon2idDefault, "testpassword", nil, nil, ErrMismatch},
	{&Argon2Params{ // NON MATCHING
		Version: Argon2id,
		Time:    1,
		Memory:  64 * 1024,
		Thread:  8, // non matching param
		Saltlen: 16,
		Keylen:  32,
		Masked:  true,
	}, Argon2idDefault, "testpassword", nil, nil, ErrMismatch},
	{&Argon2Params{ // NON MATCHING
		Version: Argon2id,
		Time:    1,
		Memory:  32 * 1024, // non matching param
		Thread:  16,
		Saltlen: 16,
		Keylen:  32,
		Masked:  true,
	}, Argon2idDefault, "testpassword", nil, nil, ErrMismatch},
	{&ScryptParams{ // ScryptDefault aka MATCHING CONDITION
		N:       1 << 16,
		R:       8,
		P:       1,
		Saltlen: 16,
		Keylen:  32,
		Masked:  true,
	}, ScryptDefault, "testpassword", nil, nil, nil},
	{&ScryptParams{ // NON MATCHING
		N:       1 << 16,
		R:       8,
		P:       1,
		Saltlen: 10, // non matching param
		Keylen:  32,
		Masked:  true,
	}, ScryptDefault, "testpassword", nil, nil, ErrMismatch},
	{&ScryptParams{ // NON MATCHING #7
		N:       1 << 16,
		R:       8,
		P:       1,
		Saltlen: 16,
		Keylen:  16, // non matching param
		Masked:  true,
	}, ScryptDefault, "testpassword", nil, nil, ErrMismatch},
	{&ScryptParams{ // NON MATCHING
		N:       1 << 16,
		R:       4, // non matching param
		P:       1,
		Saltlen: 16,
		Keylen:  32,
		Masked:  true,
	}, ScryptDefault, "testpassword", nil, nil, ErrMismatch},
	{&ScryptParams{ // NON MATCHING
		N:       1 << 14, // non matching param
		R:       8,
		P:       1,
		Saltlen: 16,
		Keylen:  32,
		Masked:  true,
	}, ScryptDefault, "testpassword", nil, nil, ErrMismatch},
}

var vectorNewCustomTestBcrypt = []struct {
	params            interface{}
	profileEqual      HashProfile
	passwordToHash    string
	expectedNewCustom error
	expectedHash      error
	expectedCompare   error
}{
	{&BcryptParams{ // MATCHING CONDITION
		Cost: bcrypt.DefaultCost,
	}, BcryptDefault, "testpassword", nil, nil, nil},
	{&BcryptParams{ // Non matching
		Cost: bcrypt.MinCost,
	}, BcryptDefault, "testpassword", nil, nil, ErrMismatch},
}

// TestFunction
func TestNew(t *testing.T) {
	for i, test := range vectorNewTests {
		myprofile, err := New(test.profile)
		if err != test.expected {
			t.Fatalf("test #%d: profile: %d err: %v vs expected: %v\n", i, myprofile, err, test.expected)
		}
	}
}

func TestCompat(t *testing.T) {
	for i, test := range vectorCompatibility {
		myprofile, err := New(test.profile)
		if test.masked {
			myprofile, err = NewMasked(test.profile)
		}

		if len(test.secret) > 0 {
			myprofile.SetKey(test.secret)
		}
		if err != nil {
			t.Fatalf("test #%d: profile: %d err: %v vs expected: %v\n", i, myprofile, err, test.want)
		}
		err = myprofile.Compare(test.hash, test.passwd)
		if err != test.want {
			t.Fatalf("test #%d: profile: %d err: %v vs expected: %v\n", i, myprofile, err, test.want)
		}
	}
}

func TestNewMasked(t *testing.T) {
	for i, test := range vectorNewMaskedTests {
		myprofile, err := NewMasked(test.profile)
		if err != test.expected {
			t.Fatalf("test #%d: profile: %d err: %v vs expected: %v\n", i, myprofile, err, test.expected)
		}
	}
}

func TestNewCustomMasked(t *testing.T) {
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

		//fmt.Printf("profile.params: %v defaut profile params: %v\n", myprofileCustom.params.Masked, scryptCommonParameters.Masked)
		// we observed a glitch here.. the #7
		//--- FAIL: TestNewCustom (2.75s)
		//    passwd_test.go:240: test #7 (passwd.Compare): profile: 2 err: <nil> vs expected: mismatch
		//
		// never been able to reproduce or find.. cosmic rays.
		// what is extremely strange is it happened on the CI/CD ONCE exactly too.
		// so i suspect a nasty bug but I suspect something related to getSalt()
		// i had a not so clean construction where the salt could not read enough bytes
		// BUT would not return an error like n, err := rand.Read( a_len_byte_array )
		// err == nil but n != len
		// could go unnoticed and generate something incorrect.. the test happens in the
		// same context.
		// other possibility would be that the profiles are not properly initialized and are referencing the same memory area
		// because i fucked up somewhere i could not find
		err = myprofileCustom.Compare(hashOrig, []byte(test.passwordToHash))
		if err != test.expectedCompare {
			t.Fatalf("test #%d (passwd.Compare): profile: %d err: %v vs expected: %v\n", i, test.profileEqual, err, test.expectedCompare)
		}
	}
}

func TestNewCustomBcrypt(t *testing.T) {
	for i, test := range vectorNewCustomTestBcrypt {
		myprofileCustom, err := NewCustom(test.params)
		if err != test.expectedNewCustom {
			t.Fatalf("test #%d: profile: %v err: %v vs expected: %v\n", i, test.params, err, test.expectedNewCustom)
		}

		myprofileOrig, err := New(test.profileEqual)
		if err != nil {
			t.Fatalf("test #%d: profile: %d err: %v vs expected: %v\n", i, test.profileEqual, err, test.expectedNewCustom)
		}
		//fmt.Printf("PROFILE ORIG: %v %T\n", myprofileOrig.t, myprofileOrig.params)

		hashCustom, err := myprofileCustom.Hash([]byte(test.passwordToHash))
		if err != test.expectedHash {
			t.Fatalf("test #%d (hash): profile: %v err: %v vs expected: %v\n", i, test.params, err, test.expectedHash)
		}

		//fmt.Printf("PROFILE ORIG: %v %T\n", myprofileOrig.t, myprofileOrig.params)
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
			t.Fatalf("test #%d (hash): profile: %d err: %v vs expected: %v\n", i, test.profile, err, test.expectedHash)
		}

		err = Compare(hash, []byte(test.passwordCompare))
		if err != test.expectedCompare {
			t.Fatalf("test #%d (Compare): profile: %d err: %v vs expected: %v\n", i, test.profile, err, test.expectedCompare)
		}

		err = myprofile.Compare(hash, []byte(test.passwordCompare))
		if err != test.expectedCompare {
			t.Fatalf("test #%d (passwd.Compare): profile: %d err: %v vs expected: %v\n", i, test.profile, err, test.expectedCompare)
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

func ExampleNewCustom() {
	customParams := Argon2Params{
		Version: Argon2id,
		Time:    1,
		Memory:  32 * 1024,
		Thread:  8,
		Saltlen: 16,
		Keylen:  32,
		Masked:  true,
	}
	p, err := NewCustom(&customParams)
	if err != nil {
		panic(err)
	}
	_, err = p.Hash([]byte("mylamepass!!"))
	if err != nil {
		panic(err)
	}
	fmt.Printf("custom argon hashed")
	// Output: custom argon hashed
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
