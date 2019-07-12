// +build go1.11

// Package passwd provides simple primitives for hashing and verifying
// password.
package passwd

import (
	"fmt"
)

//
// Goal is to provide a KISS password hashing package, that provides you with a
// way to hash and verify a password.
// The package propose a storage format output similar to other password storage
// if necessary more strong password hashing algorithm will be added.
//
// support :
//
// bcrypt (LEGACY support)
// scrypt
// argon2id
//
// a mix of (draft) RFC interpretation + documentation + cryptographer docs +
// + cryptographers (PHDs, not bloggers) friends suggestions of interpretation
// experts advices interpretation + current cryptography libs
// (libsodium, openssl and other frameworks...)
// definition/comments/etc... bits and pieces that i need to more clearly
// document to define a good baseline for those new hashing algorithms.
//
// BcryptMin
// BCRYPT_LEGACY
// BCRYPT_HARDEN
//
// ARGON2ID_MIN (unsafe usage..) TODO
// ARGON2ID_COMMON (RFC, IETF / details..)
// ARGON2ID_PARANOID
//
// SCRYPT_MIN (unsafe usage) TODO
// SCRYPT_COMMON (details..)
// SCRYPT_PARANOID
//

// HashProfile is the type that describes the exported profile type available in this
// package
type HashProfile int

// Password hashing profiles available
const (
	Argon2idDefault HashProfile = iota
	Argon2idParanoid
	ScryptDefault
	ScryptParanoid
	BcryptDefault
	BcryptParanoid
	Argon2Custom // value for custom
	ScryptCustom // value for custom
	BcryptCustom // value for custom
)

var (
	// XXX not sure yet it's the right approach
	// limiting the choice for password storage avoid shooting yourself in
	// the foot.
	params = map[HashProfile]interface{}{
		Argon2idDefault:  argonCommonParameters,
		Argon2idParanoid: argonParanoidParameters,
		ScryptDefault:    scryptCommonParameters,
		ScryptParanoid:   scryptParanoidParameters,
		BcryptDefault:    bcryptCommonParameters,
		BcryptParanoid:   bcryptParanoidParameters,
	}
)

// Profile define the hashing profile you have select and is created using
// New() / NewMasked() / NewCustom()
type Profile struct {
	t      HashProfile // type
	params interface{} // parameters
}

// New instantiate a new Profile
func New(profile HashProfile) (*Profile, error) {
	var p Profile

	switch profile {
	case Argon2idDefault, Argon2idParanoid, ScryptDefault, ScryptParanoid, BcryptDefault, BcryptParanoid:
		// all authorized
		p = Profile{
			t:      profile,
			params: params[profile],
		}
		return &p, nil
	}

	return nil, ErrUnsupported
}

// NewMasked instanciates a new masked Profile.
// "masked" translate to the fact that no hash parameters will be provided in
// the resulting hash.
func NewMasked(profile HashProfile) (*Profile, error) {
	switch profile {
	case Argon2idDefault, Argon2idParanoid, ScryptDefault, ScryptParanoid, BcryptDefault, BcryptParanoid:
		var p Profile

		// all authorized
		mparams := params[profile]

		switch v := mparams.(type) {
		case BcryptParams:
			v.Masked = true
			p = Profile{
				t:      profile,
				params: v,
			}
		case ScryptParams:
			v.Masked = true
			p = Profile{
				t:      profile,
				params: v,
			}
		case Argon2Params:
			v.Masked = true
			p = Profile{
				t:      profile,
				params: v,
			}
		}
		return &p, nil
	}

	return nil, ErrUnsupported
}

// NewCustom instanciates a new Profile using user defined hash parameters
func NewCustom(params interface{}) (*Profile, error) {
	var p Profile

	switch v := params.(type) {
	case BcryptParams:
		p = Profile{
			t:      BcryptCustom,
			params: v,
		}
		return &p, nil
	case ScryptParams:
		p = Profile{
			t:      ScryptCustom,
			params: v,
		}
		return &p, nil
	case Argon2Params:
		p = Profile{
			t:      Argon2Custom,
			params: v,
		}
		return &p, nil
	}

	return nil, ErrUnsupported
}

// Derive is the Profile's method for computing a cryptographic key
// usable with symmetric AEAD using the user provided Profile, password and salt
// it will return the derived key.
func (p *Profile) Derive(password, salt []byte) ([]byte, error) {
	switch v := p.params.(type) {
	// Bcrypt is NOT supported to derive crypto keys
	case ScryptParams:
		v.salt = salt
		return v.deriveFromPassword(password)
	case Argon2Params:
		v.salt = salt
		return v.deriveFromPassword(password)
	}
	// key, salt, nil
	return nil, ErrUnsupported
}

// Hash is the Profile's method for computing the hash value
// respective of the selected profile.
// it takes the plaintext password to hash and output its hashed value
// ready for storage
func (p *Profile) Hash(password []byte) ([]byte, error) {
	switch v := p.params.(type) {
	case BcryptParams:
		return v.generateFromPassword(password)
	case ScryptParams:
		return v.generateFromPassword(password)
	case Argon2Params:
		return v.generateFromPassword(password)
	}
	return nil, ErrUnsupported
}

// as it's a Profile method, we expect the hashed version to be already loaded
// with NewHash(hash)

// Compare method compared a computed hash against a plaintext password
// for the associated profile.
// This function is mainly here to allow to work with "masked" hashes
// where we don't provide the Hash parameters in the hashed values.
func (p *Profile) Compare(hashed, password []byte) error {
	salt, err := parseFromHashToSalt(hashed)
	if err != nil {
		fmt.Printf("compare parse error: %v\n", err)
		return ErrMismatch
	}

	switch v := p.params.(type) {
	case BcryptParams:
		return v.compare(hashed, password)
	case ScryptParams:
		v.salt = salt
		return v.compare(hashed, password)
	case Argon2Params:
		v.salt = salt
		return v.compare(hashed, password)
	}

	return ErrMismatch
}

// Compare verify a non masked hash values against a plaintext password.
func Compare(hashed, password []byte) error {
	//var version, stuff string
	//var num int
	//fmt.Printf("HASHED: %s\n", hashed)
	// FIELDS: ["2s" "ssSDTbMpkLQtIhZ558igpO" "16" "65536" "4" "32" "J/xbjklkXIhBqZ3FAF4t5xWu4rTjxr79eIjc28VYuqK"]
	// field0 : sig
	// field1 : salt
	// field2 : param0
	// field3 : param1
	// field4 : param2
	// field5 : hash

	params, err := parseFromHashToParams(hashed)
	if err != nil {
		fmt.Printf("compare parse error: %v\n", err)
		return ErrMismatch
	}

	//fmt.Printf("PARAM TYPE: %T\n", params)
	switch v := params.(type) {
	case BcryptParams:
		return v.compare(hashed, password)
	case ScryptParams:
		return v.compare(hashed, password)
	case Argon2Params:
		return v.compare(hashed, password)
	}

	return ErrMismatch
}
