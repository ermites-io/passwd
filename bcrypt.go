// +build go1.11

package passwd

import "golang.org/x/crypto/bcrypt"

var (
	BcryptMinParameters    = BcryptParams{cost: bcrypt.MinCost}
	BcryptCommonParameters = BcryptParams{cost: bcrypt.DefaultCost}
	BcryptMaxParameters    = BcryptParams{cost: bcrypt.MaxCost}
)

const (
	idBcrypt = "2a"
)

type BcryptParams struct {
	cost int
}

func (bp *BcryptParams) generateFromPassword(password []byte) ([]byte, error) {
	return bcrypt.GenerateFromPassword(password, bp.cost)
}

func (bp *BcryptParams) Compare(hashed, password []byte) error {
	return bcrypt.CompareHashAndPassword(hashed, password)
}
