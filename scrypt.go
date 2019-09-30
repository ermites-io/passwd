// +build go1.11

package passwd

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"strconv"

	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/sha3"
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
		salt:    salt,
	}

	return &sp, nil
}

func (p *ScryptParams) getSalt() error {
	p.salt = make([]byte, p.Saltlen)
	n, err := rand.Read(p.salt)
	if err != nil || n != int(p.Saltlen) {
		return err
	}
	return nil
}

func (p *ScryptParams) deriveFromPassword(password []byte) ([]byte, error) {
	key, err := scrypt.Key(password, p.salt, int(p.N), int(p.R), int(p.P), int(p.Keylen))
	if err != nil {
		return nil, err
	}
	return key, nil
}

//func (p *ScryptParams) generateFromPassword(password []byte) ([]byte, error) {
func (p *ScryptParams) generateFromParams(password []byte) ([]byte, error) {
	var hash bytes.Buffer
	var params string
	var data []byte

	data = password

	// we want to hmac a secret to have the resulting hash
	if len(p.secret) > 0 {
		// new formula.
		// 1. hashed_first_pass = hmac_sha256(password, secret:salt)
		hmac_first := hmac.New(sha3.New256, p.salt)
		_, err := hmac_first.Write(password)
		if err != nil {
			return nil, err
		}
		hmac_first_result := hmac_first.Sum(nil)

		// 2. hashed_full_pass = hmac_sha256(hashed_first_pass, secret)
		hmac_full := hmac.New(sha3.New256, p.secret)
		_, err = hmac_full.Write(hmac_first_result)
		if err != nil {
			return nil, err
		}

		// 3. p.generateFromParams(hashed_full_pass)
		data = hmac_full.Sum(nil)
	}

	key, err := scrypt.Key(data, p.salt, int(p.N), int(p.R), int(p.P), int(p.Keylen))
	if err != nil {
		return nil, err
	}

	// need to b64.
	//salt64 := base64.StdEncoding.EncodeToString(salt)
	salt64 := base64Encode(p.salt)

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

	return hash.Bytes(), nil
}

func (p *ScryptParams) generateFromPassword(password []byte) ([]byte, error) {
	err := p.getSalt()
	if err != nil {
		return nil, err
	}

	return p.generateFromParams(password)
}

func (p *ScryptParams) compare(hashed, password []byte) error {
	compared, err := p.generateFromParams(password)
	if err != nil {
		return ErrMismatch
	}

	// sanity checks.
	// we had a subtle bug where a shorter salt with the same
	// password encrypted would still match, as such you could have
	// potentially generated thousands of small salted password
	// to bruteforce and ran against the comparison function to
	// find a collision which requires less power salts HAVE to
	// be the same size that's it.
	hashlen := uint32(len(compared))
	if uint32(len(hashed)) < hashlen || len(p.salt) != int(p.Saltlen) {
		return ErrMismatch
	}

	if subtle.ConstantTimeCompare(compared, hashed[:hashlen]) == 1 {
		return nil
	}

	return ErrMismatch
}
