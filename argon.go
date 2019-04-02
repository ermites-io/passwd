// +build go1.11

package passwd

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"strconv"

	"golang.org/x/crypto/argon2"
)

const (
	ARGON2ID = iota // default
	ARGON2I
)

const (
	saltLen    = 16
	tagLen     = 32
	idArgon2i  = "2i"
	idArgon2id = "2id"
)

var (
	/*
		ArgonMinParameters = Argon2Params{
			version: ARGON2ID,
			time:    1,
			memory:  64 * 1024,
			thread:  8,
			saltlen: 16,
			keylen:  16,
		}
	*/
	ArgonCommonParameters = Argon2Params{
		version: ARGON2ID,
		time:    1,
		memory:  64 * 1024,
		thread:  8,
		saltlen: 16,
		keylen:  32,
	}
	ArgonParanoidParameters = Argon2Params{
		version: ARGON2ID,
		time:    2,
		memory:  512 * 1024,
		thread:  16,
		saltlen: 32,
		keylen:  32,
	}
)

type Argon2Params struct {
	version int
	time    uint32
	memory  uint32
	thread  uint8
	salt    []byte // on compare only..
	saltlen uint32
	keylen  uint32
	private bool // are parameters private
}

// [0] password: 'prout' hashed: '$2id$aiOE.rPFUFkkehxc6utWY.$1$65536$8$32$Wv1IMP6xwaqVaQGOX6Oxe.eSEbozeRJLzln8ZlthZfS'

func newArgon2ParamsFromFields(fields []string) (*Argon2Params, error) {
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

	// ARGON FIELD: ["mezIC/cmChATxAfFFe9ele" "2" "65536" "8" "32" "omYy81uRZcZv6JkbH17wA0s1CSpH4UQttXBB42oKMXK"]
	timeint, err := strconv.ParseInt(fields[1], 10, 32)
	if err != nil {
		return nil, err
	}
	time := uint32(timeint)

	memoryint, err := strconv.ParseInt(fields[2], 10, 32)
	if err != nil {
		return nil, err
	}
	memory := uint32(memoryint)

	threadint, err := strconv.ParseInt(fields[3], 10, 32)
	if err != nil {
		return nil, err
	}
	thread := uint8(threadint)

	keylenint, err := strconv.ParseInt(fields[4], 10, 32)
	if err != nil {
		return nil, err
	}
	keylen := uint32(keylenint)

	ap := Argon2Params{
		version: ARGON2ID, // default for now..
		time:    time,
		memory:  memory,
		thread:  thread,
		salt:    salt,
		saltlen: saltlen,
		keylen:  keylen,
	}

	return &ap, nil
}

// function that validate custom parameters and minimal security is ok.
// will upgrade over the years
func (p *Argon2Params) validate(min *Argon2Params) error {
	return nil
}

func (p *Argon2Params) Compare(hashed, password []byte) error {
	//fmt.Printf("ARGON COMPARE: \n")
	compared, err := p.generateFromParams(password)
	if err != nil {
		return err
	}

	//fmt.Printf("COMPARE %s vs %s\n", hashed, compared)

	if subtle.ConstantTimeCompare(compared, hashed) == 1 {
		return nil
	}

	return fmt.Errorf("mismatch")
}

func (p *Argon2Params) generateFromParams(password []byte) ([]byte, error) {
	var key []byte
	var id, params string
	var hash bytes.Buffer

	// need to b64.
	//salt64 := base64.StdEncoding.EncodeToString(salt)
	salt64 := base64Encode(p.salt)

	// params
	if p.private {
		params = fmt.Sprintf("%c%d%c%d%c%d%c%d",
			separatorRune, p.time,
			separatorRune, p.memory,
			separatorRune, p.thread,
			separatorRune, p.keylen)
	}

	switch p.version {
	case ARGON2I:
		id = idArgon2i
		key = argon2.Key(password, p.salt, p.time, p.memory, p.thread, p.keylen)
	case ARGON2ID:
		fallthrough
	default:
		id = idArgon2id
		key = argon2.IDKey(password, p.salt, p.time, p.memory, p.thread, p.keylen)
	}

	// encode the key
	key64 := base64Encode(key)

	passwordStr := fmt.Sprintf("%c%s%c%s%s%c%s",
		separatorRune, id,
		separatorRune, salt64,
		params,
		separatorRune, key64)
	_, err := hash.WriteString(passwordStr)
	if err != nil {
		return nil, err
	}

	// $ID$b64(SALT)$TIME$MEM$THREAD$KEYLEN$b64(ENCRYPTED)
	// ID:
	// $2D == ARGON2D
	// $2ID == ARGON2ID
	return hash.Bytes(), nil
}

func (p *Argon2Params) getSalt() error {
	p.salt = make([]byte, p.saltlen)
	n, err := rand.Read(p.salt)
	if err != nil || n != int(p.saltlen) {
		return err
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
