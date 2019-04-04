// +build go1.11

package passwd

import "golang.org/x/crypto/bcrypt"

var (
	bcryptCommonParameters   = BcryptParams{cost: bcrypt.DefaultCost}
	bcryptParanoidParameters = BcryptParams{cost: bcrypt.MaxCost}
)

const (
	idBcrypt = "2a"
)

// BcryptParams are the parameters for the bcrypt key derivation.
type BcryptParams struct {
	cost int
}

func (bp *BcryptParams) generateFromPassword(password []byte) ([]byte, error) {
	return bcrypt.GenerateFromPassword(password, bp.cost)
}

func (bp *BcryptParams) compare(hashed, password []byte) error {
	return bcrypt.CompareHashAndPassword(hashed, password)
}
