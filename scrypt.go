// +build go1.11

package passwd

import (
	"bytes"
	"crypto/subtle"
	"fmt"
	"strconv"

	"golang.org/x/crypto/scrypt"
)

const (
	idScrypt = "2s"
)

var (
	/*
		https://tools.ietf.org/html/rfc7914

		Users of scrypt can tune the parameters N, r, and p according to the
		amount of memory and computing power available, the latency-bandwidth
		product of the memory subsystem, and the amount of parallelism
		desired.  At the current time, r=8 and p=1 appears to yield good
		results, but as memory latency and CPU parallelism increase, it is
		likely that the optimum values for both r and p will increase.  Note
		also that since the computations of SMix are independent, a large
		value of p can be used to increase the computational cost of scrypt
		...
		N:
		The CPU/Memory cost parameter N ("costParameter") must be larger than 1,
		a power of 2, and less than 2 ^ (128 * r / 8).

		R:
		The parameter r ("blockSize") specifies the block size.

		P:
		The parallelization parameter p ("parallelizationParameter") is a positive integer
		less than or equal to ((2^32-1) * 32) / (128 * r)

		https://godoc.org/golang.org/x/crypto/scrypt :

		The recommended parameters for interactive logins as of 2017 are N=32768, r=8 and p=1.
		The parameters N, r, and p should be increased as memory latency and CPU parallelism increases;
		consider setting N to the highest power of 2 you can derive within 100 milliseconds.
		Remember to get a good random salt.

		another source and interpretation of those numbers by crypto gopher:
		https://blog.filippo.io/the-scrypt-parameters

	*/
	scryptMinParameters = ScryptParams{
		N:       1 << 16,
		R:       8,
		P:       1,
		Saltlen: 16,
		Keylen:  32,
		// salt
		//Masked: false,
	}

	scryptCommonParameters = ScryptParams{
		N:       1 << 16,
		R:       8,
		P:       1,
		Saltlen: 16,
		Keylen:  32,
		// salt
		//Masked: false,
	}

	scryptParanoidParameters = ScryptParams{
		N:       1 << 17,
		R:       32,
		P:       2,
		Saltlen: 32,
		Keylen:  64,
		// salt
		//Masked: false,
	}
)

// ScryptParams are the parameters for the scrypt key derivation.
type ScryptParams struct {
	N       uint32 // cpu memory cost must be > 1 && %2 == 0
	R       uint32 // parallelization cost param -> r*p < 2^30 (go implementation specific)
	P       uint32 // parallelization cost param -> r*p < 2^30 (go implementation specific)
	Saltlen uint32 // 128 bits min.
	Keylen  uint32 // 128 bits min.
	Masked  bool   // are parameters private
	salt    []byte // my salt..
	secret  []byte // secret for key'ed hashes..
}

// TODO must return salt
func newScryptParamsFromFields(fields []string) (*ScryptParams, error) {
	if len(fields) != 6 {
		return nil, ErrParse
	}

	// salt
	salt, err := base64Decode([]byte(fields[0])) // process the salt
	if err != nil {
		return nil, ErrParse
	}
	saltlen := uint32(len(salt))

	nint, err := strconv.ParseInt(fields[1], 10, 32)
	if err != nil {
		return nil, ErrParse
	}
	n := uint32(nint)

	rint, err := strconv.ParseInt(fields[2], 10, 32)
	if err != nil {
		return nil, ErrParse
	}
	r := uint32(rint)

	pint, err := strconv.ParseInt(fields[3], 10, 32)
	if err != nil {
		return nil, ErrParse
	}
	p := uint32(pint)

	keylenint, err := strconv.ParseInt(fields[4], 10, 32)
	if err != nil {
		return nil, ErrParse
	}
	keylen := uint32(keylenint)

	sp := ScryptParams{
		N:       n,
		R:       r,
		P:       p,
		Saltlen: saltlen,
		Keylen:  keylen,
		//salt:    salt,
	}

	return &sp, nil
}

// function that validate custom parameters and minimal security is ok.
// will upgrade over the years
// XXX TODO
func (p *ScryptParams) validate(min *ScryptParams) error {
	// XXX TODO
	return nil
}

func (p *ScryptParams) deriveFromPassword(password []byte) ([]byte, error) {
	key, err := scrypt.Key(password, p.salt, int(p.N), int(p.R), int(p.P), int(p.Keylen))
	if err != nil {
		return nil, err
	}
	return key, nil
}

//func (p *ScryptParams) generateFromParams(password []byte) (out []byte, err error) {
func (p *ScryptParams) generateFromParams(salt, password []byte) (out []byte, err error) {
	var hash bytes.Buffer
	var params string
	var data []byte

	// if salt mismatch, the profile dictactes, not the hash.
	// the profile dictactes
	psalt := make([]byte, p.Saltlen)
	copy(psalt, salt)

	// password
	data = password

	// we want to hmac a secret to have the resulting hash
	if len(p.secret) > 0 {
		data, err = hmacKeyHash(p.secret, psalt, password)
		if err != nil {
			return nil, err
		}
	}

	key, err := scrypt.Key(data, psalt, int(p.N), int(p.R), int(p.P), int(p.Keylen))
	if err != nil {
		return nil, err
	}

	// need to b64.
	salt64 := base64Encode(psalt)

	// params
	if !p.Masked {
		params = fmt.Sprintf("%c%d%c%d%c%d%c%d",
			separatorRune, p.N,
			separatorRune, p.R,
			separatorRune, p.P,
			separatorRune, p.Keylen)
	}

	// encode the key
	key64 := base64Encode(key)

	passwordStr := fmt.Sprintf("%c%s%c%s%s%c%s",
		separatorRune, idScrypt,
		separatorRune, salt64,
		params,
		separatorRune, key64)

	_, err = hash.WriteString(passwordStr)
	if err != nil {
		return nil, err
	}

	out = hash.Bytes()
	//return hash.Bytes(), nil
	return out, nil
}

func (p *ScryptParams) generateFromPassword(password []byte) ([]byte, error) {
	salt, err := getSalt(p.Saltlen)
	if err != nil {
		return nil, err
	}

	return p.generateFromParams(salt, password)
}

func (p *ScryptParams) compare(hashed, password []byte) error {
	salt, err := parseFromHashToSalt(hashed)
	if err != nil {
		fmt.Printf("compare parse error: %v\n", err)
		return ErrMismatch
	}

	// generate the string to compare
	compared, err := p.generateFromParams(salt, password)
	if err != nil {
		return ErrMismatch
	}

	hashlen := uint32(len(compared))
	if uint32(len(hashed)) != hashlen {
		return ErrMismatch
	}

	// the hashed[:hashlen] is to avoid padded data invalid compare while the hash is actually good
	// think like a wrongly defined database column type (i.e. char(255)) will return the string padded with spaces
	// we end up removing those case, but we bound what we check above by making sure length are identical.
	//
	//if subtle.ConstantTimeCompare(compared, hashed[:hashlen]) == 1 {
	if subtle.ConstantTimeCompare(compared, hashed) == 1 {
		return nil
	}

	return ErrMismatch
}
