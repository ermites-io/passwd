// +build go1.11

package passwd

import (
	"errors"
	"fmt"
)

//
// Goal is to provide a password wrapper, that provides you with the proper
// hash, propose a storage format output and check capabilities.
//
// support :
//
// bcrypt (LEGACY support)
// scrypt
// argon2id
//
// BcryptMin
// BCRYPT_LEGACY
// BCRYPT_HARDEN
//
// ARGON2ID_2018_MIN (details..)
// ARGON2ID_2018_COMMON (RFC, IETF / details..)
// ARGON2ID_2018_HARDENED
//
// SCRYPT_2018_MIN
// SCRYPT_2018_COMMON (details..)
// SCRYPT_2018_HARDENED
//
// roughly:
// passwd.New( strengthprofile )
// passwd.NewCustom( interface : argon_struct, scrypt_struct, bcrypt_struct )
//
// NewHash( hashedpassword )
//
//
// Password {
//   type: password
//   parameters: *params
// }
//
// func (p *Password) Derive(string) PasswordHash
// func (p *Password) CompareHashAndPassword(string
//
//
// func (ph *PasswordHash) String()

// hard part will be to define those.
const (
	Argon2idDefault = iota
	Argon2idParanoid
	ScryptDefault
	ScryptParanoid
	BcryptDefault
	BcryptParanoid
)

var (
	MyError = errors.New("file error")

	// XXX not sure yet it's the right approach
	// limiting the choice for password storage avoid shooting yourself in
	// the foot.
	Params = map[int]interface{}{
		Argon2idDefault:  ArgonCommonParameters,
		Argon2idParanoid: ArgonParanoidParameters,
		ScryptDefault:    ScryptCommonParameters,
		ScryptParanoid:   ScryptParanoidParameters,
		BcryptDefault:    BcryptCommonParameters,
		BcryptParanoid:   BcryptParanoidParameters,
	}
)

// password.Profile
type Profile struct {
	t      int         // type
	params interface{} // parameters
}

func (p *Profile) Hash(password []byte) ([]byte, error) {
	switch v := p.params.(type) {
	case BcryptParams:
		return v.generateFromPassword(password)
	case ScryptParams:
		return v.generateFromPassword(password)
	case Argon2Params:
		return v.generateFromPassword(password)
	default:
		fmt.Printf("unsupported\n")
		panic("unsupported")
	}

	return nil, MyError
}

// as it's a Profile method, we expect the hashed version to be already loaded
// with NewHash(hash)
func (p *Profile) Compare(password []byte) error {
	return nil
}

func New(profile int) *Profile {
	p := Profile{
		t:      profile,
		params: Params[profile],
	}
	return &p
}

func NewCustom(params interface{}) *Profile {
	switch v := params.(type) {
	case BcryptParams:
		return &Profile{
			t:      -1,
			params: v,
		}
	case ScryptParams:
		return &Profile{
			t:      -1,
			params: v,
		}
	case Argon2Params:
		return &Profile{
			t:      -1,
			params: v,
		}
	default:
		fmt.Printf("Unsupported\n")
		panic("unsupported")
	}
}

func NewHash(hashed []byte) *Profile {
	return nil
}

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
		return err
	}

	//fmt.Printf("PARAM TYPE: %T\n", params)
	switch v := params.(type) {
	case BcryptParams:
		return v.Compare(hashed, password)
	case ScryptParams:
		return v.Compare(hashed, password)
	case Argon2Params:
		//fmt.Printf("ARGON2 PARAM FOUND\n")
		return v.Compare(hashed, password)
	}

	return fmt.Errorf("mismatch")
}

/*
func main() {
	fmt.Printf("password package test\n")
	p := New(Argon2idCommon)
	h, err := p.Hash([]byte(os.Args[1]))
	if err != nil {
		log.Fatalf("err: %v\n", err)
	}
	fmt.Printf("Hashed: %s\n", h)
	fmt.Printf("ARGON RC: %v\n", Compare(h, []byte("prout")))

	fmt.Printf("-------\n")
	// dsdslk
	b := New(BcryptMin)
	hb, err := b.Hash([]byte(os.Args[1]))
	if err != nil {
		log.Fatalf("err: %v\n", err)
	}
	fmt.Printf("Hashed: %s\n", hb)
	fmt.Printf("BCRYPT RC: %v\n", Compare(hb, []byte("prout")))
	fmt.Printf("-------\n")

	// dkskdal
	s := New(ScryptMin)
	hs, err := s.Hash([]byte(os.Args[1]))
	if err != nil {
		log.Fatalf("err: %v\n", err)
	}
	fmt.Printf("Hashed: %s\n", hs)
	fmt.Printf("SCRYPT RC: %v\n", Compare(hs, []byte("prout")))
	fmt.Printf("-------\n")

	// let's compare now
	//hbp := NewHash(hb)
	// password.Compare()

	// string:
	// tets
	// bcrypt go:
	// $2a$04$bxM4yM6AlSXN3m6r4b4cUuVjYOQnsToE0Xsp31EWRnW6AO1/bD27u
	// bcrypt obsd:
	// TODO
	// argon2id:
	// $2id$hbXDLYjXgkx7rVDpymx8h.$2$262144$8$32$ZhSyCEg.MCqBAwAEKAtd1IPxgw5t393tkDrZ.bnBXRK
	// scrypt:
	// $2s$
	//p := NewHash
}
*/
