package password

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2Config initialize the config require to create a hash function
type Argon2Config struct {
	Time        int
	Memory      int
	Parallelism int
	KeyLen      int
	SaltLen     int
	Variant     Variant
}

type argon2Hasher struct {
	config Argon2Config
}

func NewArgonPasswordHasher(config Argon2Config) (Hasher, error) {
	if config.KeyLen <= 0 {
		config.KeyLen = Argon2DefaultKeyLength
	}
	if config.Time <= 0 {
		config.Time = Argon2DefaultTime
	}
	if config.Memory <= 0 {
		config.Memory = Argon2DefaultMemory
	}
	if config.Parallelism <= 0 {
		config.Parallelism = Argon2DefaultParallelism
	}
	if config.Variant < 0 || config.Variant > 1 {
		config.Variant = Argon2DefaultVariant
	}
	if config.SaltLen <= 0 {
		config.SaltLen = Argon2DefaultSaltLength
	}

	return &argon2Hasher{config: config}, nil
}

// Variant sets up enum for available Argon2 variants
type Variant int

const (
	// Argon2IDVariant points to Argon2 id variant
	Argon2IDVariant Variant = iota
	// Argon2ID points to Argon2 i variant
	Argon2ID
)

const (
	// Argon2DefaultKeyLength is the desired number of returned bytes
	Argon2DefaultKeyLength = 64
	// Argon2DefaultTime is the number of iterations to perform
	Argon2DefaultTime = 16
	// Argon2DefaultMemory is the amount of memory (in kilobytes) to use
	Argon2DefaultMemory = 64 * 1024
	// Argon2DefaultParallelism is the degree of parallelism (i.e. number of threads)
	Argon2DefaultParallelism = 4
	// Argon2DefaultVariant combines the Argon2d and Argon2i
	Argon2DefaultVariant = Argon2IDVariant
	// Argon2DefaultSaltLength is the default salt length in bytes.
	Argon2DefaultSaltLength = 32
)

// Hash creates a PHC-formatted hash with config provided
//
//	package main
//
//	import (
//		"fmt"
//		"github.com/aldy505/phc-crypto/argon2"
//	)
//
//	func main() {
//		hash, err := argon2.Hash("password", argon2.Argon2Config{
//			Parallelism: 3,
//			Variant: argon2.Argon2ID,
//		})
//		if err != nil {
//			fmt.Println(err)
//		}
//		fmt.Println(hash) // $argon2i$v=19$m=65536,t=16,p=3$8400b4e5f01f30092b794de34c61a6fdfea6b6b446560fda08a876bd11e9c62e$3fd77927d189...
//	}
func (a *argon2Hasher) Hash(ctx context.Context, plainPassword string) (string, error) {
	if plainPassword == "" {
		return "", ErrEmptyToken
	}

	// random-generated salt (16 bytes recommended for password hashing)
	salt := make([]byte, a.config.SaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("reading random reader: %w", err)
	}

	var hash []byte
	if a.config.Variant == Argon2IDVariant {
		hash = argon2.IDKey([]byte(plainPassword), salt, uint32(a.config.Time), uint32(a.config.Memory), uint8(a.config.Parallelism), uint32(a.config.KeyLen))
	} else if a.config.Variant == Argon2ID {
		hash = argon2.Key([]byte(plainPassword), salt, uint32(a.config.Time), uint32(a.config.Memory), uint8(a.config.Parallelism), uint32(a.config.KeyLen))
	}
	version := argon2.Version
	hashString := serialize(phcConfig{
		ID:      "argon2" + returnArgon2Variant(a.config.Variant),
		Version: version,
		Params: map[string]interface{}{
			"m": a.config.Memory,
			"t": a.config.Time,
			"p": a.config.Parallelism,
		},
		Salt: hex.EncodeToString(salt),
		Hash: hex.EncodeToString(hash),
	})
	return hashString, nil
}

// Verify checks the hash if it's equal (by an algorithm) to plain text provided.
//
//	package main
//
//	import (
//	  "fmt"
//	  "github.com/aldy505/phc-crypto/argon2"
//	)
//
//	func main() {
//	  hash := "$argon2i$v=19$m=65536,t=16,p=3$8400b4e5f01f30092b794de34c61a6fdfea6b6b446560fda08a876bd11e9c62e$3fd77927d189..."
//
//	  verify, err := argon2.Verify(hash, "password")
//	  if err != nil {
//	    fmt.Println(err)
//	  }
//	  fmt.Println(verify) // true
//	}
func (a *argon2Hasher) Verify(ctx context.Context, plainPassword string, hashedPassword string) (bool, error) {
	if plainPassword == "" || hashedPassword == "" {
		return false, ErrEmptyToken
	}

	deserialized := deserialize(hashedPassword)
	if !strings.HasPrefix(deserialized.ID, "argon2") {
		return false, ErrUnexpectedHasherInstance
	}

	var verifyHash []byte
	decodedHash, err := hex.DecodeString(deserialized.Hash)
	if err != nil {
		return false, err
	}
	keyLen := uint32(len(decodedHash))

	time, err := strconv.ParseUint(deserialized.Params["t"].(string), 10, 32)
	if err != nil {
		return false, err
	}
	memory, err := strconv.ParseUint(deserialized.Params["m"].(string), 10, 32)
	if err != nil {
		return false, err
	}
	parallelism, err := strconv.ParseUint(deserialized.Params["p"].(string), 10, 32)
	if err != nil {
		return false, err
	}

	salt, err := hex.DecodeString(deserialized.Salt)
	if err != nil {
		return false, err
	}

	if deserialized.ID == "argon2id" {
		verifyHash = argon2.IDKey([]byte(plainPassword), salt, uint32(time), uint32(memory), uint8(parallelism), keyLen)
	} else if deserialized.ID == "argon2i" {
		verifyHash = argon2.Key([]byte(plainPassword), salt, uint32(time), uint32(memory), uint8(parallelism), keyLen)
	}

	if subtle.ConstantTimeCompare(verifyHash, decodedHash) == 1 {
		return true, nil
	}
	return false, nil
}

// returnArgon2Variant converts enum variant to string for serializing hash
func returnArgon2Variant(variant Variant) string {
	if variant == Argon2IDVariant {
		return "id"
	} else if variant == Argon2ID {
		return "i"
	}
	return ""
}
