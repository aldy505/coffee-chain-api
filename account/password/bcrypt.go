package password

import (
	"context"
	"encoding/hex"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

type bcryptHasher struct {
	Rounds int
}

func NewBcryptPasswordHasher(rounds int) (Hasher, error) {
	if rounds <= 0 {
		rounds = BcryptDefaultRounds
	}

	return &bcryptHasher{Rounds: rounds}, nil
}

const (
	// BcryptDefaultRounds is the cost of rounds, minimum of 4, maximum of 31.
	BcryptDefaultRounds = 10
)

// Hash creates a PHC-formatted hash with config provided
//
//	import (
//	  "fmt"
//	  "github.com/aldy505/phc-crypto/bcrypt"
//	)
//
//	func main() {
//	  hash, err := bcrypt.Hash("password", bcrypt.Config{
//	    Rounds: 12,
//	  })
//	  if err != nil {
//	    fmt.Println(err)
//	  }
//	  fmt.Println(hash) // $bcrypt$v=0$r=12$$2432612431322479356256373563666e503557...
//	}
func (b *bcryptHasher) Hash(ctx context.Context, plainPassword string) (string, error) {
	if plainPassword == "" {
		return "", ErrEmptyToken
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(plainPassword), b.Rounds)
	if err != nil {
		return "", err
	}

	hashString := serialize(phcConfig{
		ID:      "bcrypt",
		Version: 0,
		Params: map[string]interface{}{
			"r": b.Rounds,
		},
		Hash: hex.EncodeToString(hash),
	})
	return hashString, nil
}

// Verify checks the hash if it's equal (by an algorithm) to plain text provided.
//
//	import (
//	  "fmt"
//	  "github.com/aldy505/phc-crypto/bcrypt"
//	)
//
//	func main() {
//	  hash := "$bcrypt$v=0$r=12$$2432612431322479356256373563666e503557..."
//
//	  verify, err := bcrypt.Verify(hash, "password")
//	  if err != nil {
//	    fmt.Println(err)
//	  }
//	  fmt.Println(verify) // true
//	}
func (b *bcryptHasher) Verify(ctx context.Context, plainPassword string, hashedPassword string) (bool, error) {
	if plainPassword == "" || hashedPassword == "" {
		return false, ErrEmptyToken
	}

	deserialized := deserialize(hashedPassword)
	if !strings.HasPrefix(deserialized.ID, "bcrypt") {
		return false, ErrUnexpectedHasherInstance
	}
	decodedHash, err := hex.DecodeString(deserialized.Hash)
	if err != nil {
		return false, err
	}
	err = bcrypt.CompareHashAndPassword(decodedHash, []byte(plainPassword))
	if err != nil {
		return false, nil
	}
	return true, nil
}
