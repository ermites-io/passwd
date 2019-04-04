// +build go1.11

package passwd

import (
	"bytes"
	"crypto/rand"
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

	*/
	scryptCommonParameters = ScryptParams{
		n:       65536,
		r:       8,
		p:       1,
		saltlen: 16,
		keylen:  32,
		masked:  false,
	}

	scryptParanoidParameters = ScryptParams{
		n:       65536,
		r:       32,
		p:       2,
		saltlen: 32,
		keylen:  64,
		masked:  false,
	}
)

// ScryptParams are the parameters for the scrypt key derivation.
type ScryptParams struct {
	n       uint32 // cpu memory cost must be > 1 && %2 == 0
	r       uint32 // parallelization cost param -> r*p < 2^30 (go implementation specific)
	p       uint32 // parallelization cost param -> r*p < 2^30 (go implementation specific)
	salt    []byte // my salt..
	saltlen uint32 // 128 bits min.
	keylen  uint32 // 128 bits min.
	masked  bool   // are parameters private
}

func newScryptParamsFromFields(fields []string) (*ScryptParams, error) {
	if len(fields) != 6 {
		return nil, fmt.Errorf("invalid hash")
	}

	//fmt.Printf("ARGON FIELD: %q\n", fields)
	// salt
	salt, err := base64Decode([]byte(fields[0])) // process the salt
	if err != nil {
		return nil, err
	}
	saltlen := uint32(len(salt))

	nint, err := strconv.ParseInt(fields[1], 10, 32)
	if err != nil {
		return nil, err
	}
	n := uint32(nint)

	rint, err := strconv.ParseInt(fields[2], 10, 32)
	if err != nil {
		return nil, err
	}
	r := uint32(rint)

	pint, err := strconv.ParseInt(fields[3], 10, 32)
	if err != nil {
		return nil, err
	}
	p := uint32(pint)

	keylenint, err := strconv.ParseInt(fields[4], 10, 32)
	if err != nil {
		return nil, err
	}
	keylen := uint32(keylenint)

	sp := ScryptParams{
		n:       n,
		r:       r,
		p:       p,
		salt:    salt,
		saltlen: saltlen,
		keylen:  keylen,
	}

	return &sp, nil
}

func (p *ScryptParams) getSalt() error {
	p.salt = make([]byte, p.saltlen)
	n, err := rand.Read(p.salt)
	if err != nil || n != int(p.saltlen) {
		return err
	}
	return nil
}

//func (p *ScryptParams) generateFromPassword(password []byte) ([]byte, error) {
func (p *ScryptParams) generateFromParams(password []byte) ([]byte, error) {
	var hash bytes.Buffer
	var params string

	// need to b64.
	//salt64 := base64.StdEncoding.EncodeToString(salt)
	salt64 := base64Encode(p.salt)

	// params
	if !p.masked {
		params = fmt.Sprintf("%c%d%c%d%c%d%c%d",
			separatorRune, p.n,
			separatorRune, p.r,
			separatorRune, p.p,
			separatorRune, p.keylen)
	}
	id := idScrypt

	key, err := scrypt.Key(password, p.salt, int(p.r), int(p.n), int(p.p), int(p.keylen))
	if err != nil {
		return nil, err
	}

	// encode the key
	key64 := base64Encode(key)

	passwordStr := fmt.Sprintf("%c%s%c%s%s%c%s",
		separatorRune, id,
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
		return err
	}

	if subtle.ConstantTimeCompare(compared, hashed) == 1 {
		return nil
	}

	return ErrMismatch
}
