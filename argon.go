// +build go1.12

package passwd

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"strconv"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/sha3"
)

const (
	// Argon2id constant is to select the argon flavor in Argon2Params version field
	Argon2id = iota // default
	// Argon2i constant is to select argon flavor in Argon2Params version field
	Argon2i
)

const (
	idArgon2i  = "2i"
	idArgon2id = "2id"
)

var (

	/*
		not everything is clear in the draft:
		https://datatracker.ietf.org/doc/draft-irtf-cfrg-argon2/?include_text=1

		however

		9.4.  Recommendations

		The Argon2id variant with t=1 and maximum available memory is
		recommended as a default setting for all environments.  This setting
		is secure against side-channel attacks and maximizes adversarial
		costs on dedicated bruteforce hardware.

		we're running with concurrent authentication requests, I cannot suck as much memory,
		default safety will be 64MB in cloud environment.

		if you're using this for storing password for a more dedicated resource and you wish to put pain
		on attackers, go for the paranoid or a custom definition.

		the purpose of the package is to help with comparison and hashing + format, nothing more nothing less

	*/
	argonMinParameters = Argon2Params{
		Version: Argon2id,
		Time:    1,
		Memory:  16 * 1024,
		Thread:  8,
		Saltlen: 16,
		Keylen:  16,
		//salt
		//masked: false,
	}

	// XXX need more test/analysis
	argonCommonParameters = Argon2Params{
		Version: Argon2id,
		Time:    1,
		Memory:  64 * 1024,
		Thread:  16,
		Saltlen: 16,
		Keylen:  32,
		//salt
		//masked: false,
	}

	// XXX need more test/analysis
	argonParanoidParameters = Argon2Params{
		Version: Argon2id,
		Time:    2,
		Memory:  512 * 1024,
		Thread:  32,
		Saltlen: 32,
		Keylen:  64,
		//salt
		//masked: false,
	}
)

// Argon2Params are the parameters for the argon2 key derivation.
type Argon2Params struct {
	Version int
	Time    uint32
	Memory  uint32
	Saltlen uint32
	Keylen  uint32
	Thread  uint8
	Masked  bool   // are parameters private
	salt    []byte // on compare only..
	secret  []byte // secret for key'ed hashes..
}

// [0] password: 'prout' hashed: '$2id$aiOE.rPFUFkkehxc6utWY.$1$65536$8$32$Wv1IMP6xwaqVaQGOX6Oxe.eSEbozeRJLzln8ZlthZfS'
func newArgon2ParamsFromFields(fields []string) (*Argon2Params, error) {
	if len(fields) != 6 {
		return nil, ErrParse
	}

	// salt
	salt, err := base64Decode([]byte(fields[0])) // process the salt
	if err != nil {
		return nil, ErrParse
	}
	saltlen := uint32(len(salt))

	// ARGON FIELD: ["mezIC/cmChATxAfFFe9ele" "2" "65536" "8" "32" "omYy81uRZcZv6JkbH17wA0s1CSpH4UQttXBB42oKMXK"]
	timeint, err := strconv.ParseInt(fields[1], 10, 32)
	if err != nil {
		return nil, ErrParse
	}
	time := uint32(timeint)

	memoryint, err := strconv.ParseInt(fields[2], 10, 32)
	if err != nil {
		return nil, ErrParse
	}
	memory := uint32(memoryint)

	threadint, err := strconv.ParseInt(fields[3], 10, 32)
	if err != nil {
		return nil, ErrParse
	}
	thread := uint8(threadint)

	keylenint, err := strconv.ParseInt(fields[4], 10, 32)
	if err != nil {
		return nil, ErrParse
	}
	keylen := uint32(keylenint)

	// we just what we need.
	ap := Argon2Params{
		Version: Argon2id, // default for now..
		Time:    time,
		Memory:  memory,
		Thread:  thread,
		Saltlen: saltlen,
		Keylen:  keylen,
		salt:    salt,
	}

	return &ap, nil
}

// function that validate custom parameters and minimal security is ok.
// will upgrade over the years
// XXX TODO
func (p *Argon2Params) validate(min *Argon2Params) error {
	// XXX TODO
	return nil
}

func (p *Argon2Params) compare(hashed, password []byte) error {
	compared, err := p.generateFromParams(password)
	if err != nil {
		return ErrMismatch
	}

	// yes in case things are padded by mistake depending on storage
	// whatever.. the params tells us what to verify.
	//
	// we had a subtle bug where a shorter salt with the same
	// password encrypted would still match, as such you could have
	// potentially generated thousands of small salted password
	// to bruteforce and ran against the comparison function to
	// find a collision which requires less power, salts HAVE to
	// be the same size that's it.
	hashlen := uint32(len(compared))
	if uint32(len(hashed)) != hashlen || len(p.salt) != int(p.Saltlen) {
		return ErrMismatch
	}

	//fmt.Printf("COMPARE (%d)%s vs (%d)%s\n", len(hashed), hashed, len(compared), compared)
	if subtle.ConstantTimeCompare(compared, hashed[:hashlen]) == 1 {
		return nil
	}

	return ErrMismatch
}

func (p *Argon2Params) deriveFromPassword(password []byte) (key []byte, err error) {
	err = p.validate(&argonMinParameters)
	if err != nil {
		return nil, err
	}

	switch p.Version {
	case Argon2i:
		key = argon2.Key(password, p.salt, p.Time, p.Memory, p.Thread, p.Keylen)
	case Argon2id:
		fallthrough
	default:
		key = argon2.IDKey(password, p.salt, p.Time, p.Memory, p.Thread, p.Keylen)
	}

	return key, nil
}

/*
func hmacKeyHash(secret, salt, password []byte) ([]byte, error) {
}
*/

func (p *Argon2Params) generateFromParams(password []byte) ([]byte, error) {
	var key []byte
	var id, params string
	var hash bytes.Buffer
	var data []byte

	err := p.validate(&argonMinParameters)
	if err != nil {
		return nil, err
	}

	data = password

	// we want to hmac a secret to have the resulting hash
	if len(p.secret) > 0 {
		//fmt.Printf("secret enabled\n")
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

		data = hmac_full.Sum(nil)
	}

	switch p.Version {
	case Argon2i:
		id = idArgon2i
		key = argon2.Key(data, p.salt, p.Time, p.Memory, p.Thread, p.Keylen)
	case Argon2id:
		fallthrough
	default:
		id = idArgon2id
		key = argon2.IDKey(data, p.salt, p.Time, p.Memory, p.Thread, p.Keylen)
	}

	// need to b64.
	//salt64 := base64.StdEncoding.EncodeToString(salt)
	salt64 := base64Encode(p.salt)

	// params
	if !p.Masked {
		params = fmt.Sprintf("%c%d%c%d%c%d%c%d",
			separatorRune, p.Time,
			separatorRune, p.Memory,
			separatorRune, p.Thread,
			separatorRune, p.Keylen)
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

	// $ID$b64(SALT)$TIME$MEM$THREAD$KEYLEN$b64(ENCRYPTED)
	// ID:
	// $2D == ARGON2D
	// $2ID == Argon2id
	return hash.Bytes(), nil
}

func (p *Argon2Params) getSalt() error {
	p.salt = make([]byte, p.Saltlen)
	n, err := rand.Read(p.salt)
	if err != nil || n != int(p.Saltlen) {
		return ErrHash
	}
	return nil
}

func (p *Argon2Params) generateFromPassword(password []byte) ([]byte, error) {

	err := p.getSalt()
	if err != nil {
		return nil, err
	}

	return p.generateFromParams(password)
}
