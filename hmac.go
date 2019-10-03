// +build go1.12

package passwd

import (
	"crypto/hmac"
	"crypto/rand"

	"golang.org/x/crypto/sha3"
)

func getSalt(sz uint32) ([]byte, error) {
	salt := make([]byte, sz)
	n, err := rand.Read(salt)
	if err != nil || n != int(sz) {
		return nil, errSalt
	}
	return salt, nil
}

func hmacKeyHash(secret, salt, password []byte) (hret []byte, err error) {
	// new formula.
	// 1. hashed_first_pass = hmac_sha3-256(password, secret:salt)
	h := hmac.New(sha3.New256, salt)
	_, err = h.Write(password)
	if err != nil {
		return nil, err
	}
	hResult := h.Sum(nil)

	// 2. hashed_full_pass = hmac_sha3-384(hashed_first_pass, secret)
	hFinal := hmac.New(sha3.New384, secret)
	_, err = hFinal.Write(hResult)
	if err != nil {
		return nil, err
	}

	hret = hFinal.Sum(nil)
	return hret, nil
}
