package reset

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"runtime"
	"time"

	xcha "golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/sha3"
)

// Code defines the content of the reset code
// an expiration time boundary and user supplied data.
type Code struct {
	Time     int64
	Userdata []byte // store what you need for your app.
}

const (
	// DefaultExpiration defines the proposed expiration TTL of the reset
	// codes.
	DefaultExpiration = 10 * time.Minute
	// ExpiryOneHour defines a one hour duration for expiration.
	ExpiryOneHour = 1 * time.Hour
	// ExpiryOneDay defines a one day duration for the reset code
	// expiration.
	ExpiryOneDay = 24 * time.Hour
)

func zero(buffer []byte) {
	for i, _ := range buffer {
		buffer[i] = 0x00
	}
	runtime.KeepAlive(buffer)
}

func zero32(buffer [32]byte) {
	for i, _ := range buffer {
		buffer[i] = 0x00
	}
	runtime.KeepAlive(buffer)
}

// NewCode creates a new packed reset.Code embedding userdata and valid for d
// time.Duration using hashed password.
func NewCode(hashed, userdata []byte, d time.Duration) (string, error) {
	var nilstr string

	r := Code{
		Time:     time.Now().Add(d).Unix(),
		Userdata: []byte(userdata),
	}

	m, err := json.Marshal(&r)
	if err != nil {
		return nilstr, err
	}

	// i need to wipe both at the end.
	keysha := sha3.Sum256(hashed)
	key := keysha[:]
	// wipe key on exit
	defer zero(key)
	defer zero32(keysha)

	nonce := make([]byte, xcha.NonceSizeX)
	_, err = rand.Read(nonce)
	if err != nil {
		return nilstr, err
	}
	c, err := xcha.NewX(key)
	if err != nil {
		return nilstr, err
	}

	ciphertext := c.Seal(nonce, nonce, m, nonce)
	return base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

// VerifyCode verify the provided code using hashed password and returns the
// embedded userdata.
func VerifyCode(hashed []byte, code string) ([]byte, error) {
	var r Code

	rawcode, err := base64.RawURLEncoding.DecodeString(code)
	if err != nil {
		return nil, err
	}

	if len(rawcode) <= xcha.NonceSizeX {
		return nil, fmt.Errorf("invalid input")
	}

	keysha := sha3.Sum256(hashed)
	key := keysha[:]
	// wipe key on exit
	defer zero(key)
	defer zero32(keysha)

	nonce := rawcode[:xcha.NonceSizeX]
	ciphertext := rawcode[xcha.NonceSizeX:]

	c, err := xcha.NewX(key)
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

	if timenow.After(timeCode) {
		return nil, fmt.Errorf("expired")
	}

	return r.Userdata, nil
}
