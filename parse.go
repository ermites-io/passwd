// +build go1.12

package passwd

import (
	"strings"
	"unicode"

	"golang.org/x/text/unicode/rangetable"
)

const (
	separatorRune = rune('$')
)

var (
	rangeTableSeparator = rangetable.New(separatorRune)
)

func token(c rune) bool {
	return unicode.Is(rangeTableSeparator, c)
}

func parseFromHashToParams(hashed []byte) (interface{}, error) {
	fields := strings.FieldsFunc(string(hashed), token)
	if len(fields) < 2 {
		return nil, ErrParse
	}

	switch fields[0] {
	case idBcrypt:
		bp, err := newBcryptParamsFromHash(hashed)
		if err != nil {
			return nil, err
		}

		return bp, nil
	case idScrypt:
		//fmt.Printf("scrypt compare!\n")
		sp, err := newScryptParamsFromFields(fields[1:]) // mismatch.
		if err != nil {
			// XXX wrapp the error
			return nil, err
		}
		return sp, nil
	case idArgon2i:
		fallthrough
	case idArgon2id:
		ap, err := newArgon2ParamsFromFields(fields[1:]) // mismatch.
		if err != nil {
			// XXX wrapp the error
			return nil, err
		}
		return ap, nil
	}
	return nil, ErrParse
}

func parseFromHashToSalt(hashed []byte) ([]byte, error) {
	fields := strings.FieldsFunc(string(hashed), token)
	if len(fields) < 2 {
		return nil, ErrParse
	}
	switch fields[0] {
	case idBcrypt:
		return nil, nil
	case idScrypt:
		fallthrough
	case idArgon2i:
		fallthrough
	case idArgon2id: // with different salt len it might have matched.
		salt, err := base64Decode([]byte(fields[1])) // process the salt
		if err != nil {
			return nil, ErrParse
		}
		return salt, nil
	}
	return nil, ErrParse

}
