package reset

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	xcha "golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/sha3"
)

type Code struct {
	Time     int64
	Userdata []byte // store what you need for your app.
}

var (
	DefaultExpiration = 10 * time.Minute
)

func NewCode(hashed, userdata []byte, d time.Duration) string {

	fmt.Printf("hashed: %s\n", hashed)
	fmt.Printf("userdata: %s\n", userdata)

	r := Code{
		Time:     time.Now().Add(d).Unix(),
		Userdata: []byte(userdata),
	}

	m, err := json.Marshal(&r)
	if err != nil {
		panic(err)
	}

	keysha := sha3.Sum256(hashed)
	// TODO wipe key
	nonce := make([]byte, xcha.NonceSizeX)

	_, err = rand.Read(nonce)
	if err != nil {
		panic(err)
	}
	c, err := xcha.NewX(keysha[:])
	if err != nil {
		panic(err)
	}

	ciphertext := c.Seal(nonce, nonce, m, nonce)
	return base64.RawURLEncoding.EncodeToString(ciphertext)
}

func ValidateResetCode(hashed []byte, code string) ([]byte, error) {
	var r Code

	rawcode, err := base64.RawURLEncoding.DecodeString(code)
	if err != nil {
		return nil, err
	}

	if len(rawcode) <= xcha.NonceSizeX {
		return nil, fmt.Errorf("invalid")
	}

	keysha := sha3.Sum256(hashed)
	nonce := rawcode[:xcha.NonceSizeX]
	ciphertext := rawcode[xcha.NonceSizeX:]

	c, err := xcha.NewX(keysha[:])
	if err != nil {
		return nil, err
	}

	plaintext, err := c.Open(nil, nonce, ciphertext, nonce)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(plaintext, &r)
	if err != nil {
		return nil, err
	}

	timeCode := time.Unix(r.Time, 0)
	timenow := time.Now()

	fmt.Printf("now: %v code: %v\n", timenow.Unix(), r.Time)

	if timenow.After(timeCode) {
		return nil, fmt.Errorf("expired")
	}

	return r.Userdata, nil
}
