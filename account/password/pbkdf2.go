package password

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// Pbdkf2Config initialize the config require to create a hash function
type Pbdkf2Config struct {
	Rounds   int
	KeyLen   int
	HashFunc HashFunction
	SaltLen  int
}

type pbdkf2Hasher struct {
	config Pbdkf2Config
}

func NewPbdkf2PasswordHasher(config Pbdkf2Config) (Hasher, error) {
	if config.Rounds <= 0 {
		config.Rounds = Pbdkf2DefaultRounds
	}
	if config.KeyLen <= 0 {
		config.KeyLen = Pbdkf2DefaultKeyLength
	}
	if config.HashFunc < 0 || config.HashFunc > 5 {
		config.HashFunc = Pbdkf2DefaultHashFunction
	}
	if config.SaltLen <= 0 {
		config.SaltLen = Pbdkf2DefaultSaltLength
	}

	return &pbdkf2Hasher{config: config}, nil
}

const (
	// Pbdkf2DefaultRounds is the iteration counts.
	Pbdkf2DefaultRounds = 4096
	// Pbdkf2DefaultKeyLength is how many bytes to generate as output.
	Pbdkf2DefaultKeyLength = 32
	// Pbdkf2DefaultHashFunction is for calculating HMAC. Defaulting to sha256.
	Pbdkf2DefaultHashFunction = SHA256
	// Pbdkf2DefaultSaltLength is the default salth length in bytes.
	Pbdkf2DefaultSaltLength = 16
)

type HashFunction int

const (
	SHA1 HashFunction = iota
	SHA256
	SHA224
	SHA512
	SHA384
	MD5
)

func hashFuncToName(h HashFunction) string {
	switch h {
	case SHA1:
		return "sha1"
	case SHA256:
		return "sha256"
	case SHA224:
		return "sha224"
	case SHA512:
		return "sha512"
	case SHA384:
		return "sha384"
	case MD5:
		return "md5"
	default:
		return ""
	}
}

// Hash creates a PHC-formatted hash with config provided
//
//	import (
//	  "fmt"
//	  "github.com/aldy505/phc-crypto/pbkdf2"
//	)
//
//	func main() {
//	  hash, err := pbkdf2.Hash("password", pbkdf2.Pbdkf2Config{
//	    HashFunc: pbkdf2.SHA512,
//	  })
//	  if err != nil {
//	    fmt.Println(err)
//	  }
//	  fmt.Println(hash) // $pbkdf2sha512$v=0$i=4096$87a39b3cf30626bc7cf6534ac3a14ddf$d32093416bf521ff0...
//	}
func (p *pbdkf2Hasher) Hash(ctx context.Context, plainPassword string) (string, error) {
	if plainPassword == "" {
		return "", ErrEmptyToken
	}

	// minimum 64 bits, 128 bits is recommended
	salt := make([]byte, p.config.SaltLen)
	io.ReadFull(rand.Reader, salt)

	var hash []byte

	switch p.config.HashFunc {
	case SHA1:
		hash = pbkdf2.Key([]byte(plainPassword), salt, p.config.Rounds, p.config.KeyLen, sha1.New)
	case SHA256:
		hash = pbkdf2.Key([]byte(plainPassword), salt, p.config.Rounds, p.config.KeyLen, sha256.New)
	case SHA224:
		hash = pbkdf2.Key([]byte(plainPassword), salt, p.config.Rounds, p.config.KeyLen, sha256.New224)
	case SHA512:
		hash = pbkdf2.Key([]byte(plainPassword), salt, p.config.Rounds, p.config.KeyLen, sha512.New)
	case SHA384:
		hash = pbkdf2.Key([]byte(plainPassword), salt, p.config.Rounds, p.config.KeyLen, sha512.New384)
	case MD5:
		hash = pbkdf2.Key([]byte(plainPassword), salt, p.config.Rounds, p.config.KeyLen, md5.New)
	}

	hashString := serialize(phcConfig{
		ID: "pbkdf2" + hashFuncToName(p.config.HashFunc),
		Params: map[string]interface{}{
			"i": p.config.Rounds,
		},
		Salt: hex.EncodeToString(salt[:]),
		Hash: hex.EncodeToString(hash[:]),
	})

	return hashString, nil
}

// Verify checks the hash if it's equal (by an algorithm) to plainPassword text provided.
//
//	import (
//	  "fmt"
//	  "github.com/aldy505/phc-crypto/pbkdf2"
//	)
//
//	func main() {
//	  hash := "$pbkdf2sha512$v=0$i=4096$87a39b3cf30626bc7cf6534ac3a14ddf$d32093416bf521ff0..."
//
//	  verify, err := pbkdf2.Verify(hash, "password")
//	  if err != nil {
//	    fmt.Println(err)
//	  }
//	  fmt.Println(verify) // true
//	}
func (p *pbdkf2Hasher) Verify(ctx context.Context, plainPassword string, hashedPassword string) (bool, error) {
	if hashedPassword == "" || plainPassword == "" {
		return false, ErrEmptyToken
	}

	deserialized := deserialize(hashedPassword)

	if !strings.HasPrefix(deserialized.ID, "pbkdf2") {
		return false, ErrUnexpectedHasherInstance
	}

	decodedHash, err := hex.DecodeString(deserialized.Hash)
	if err != nil {
		return false, err
	}
	keyLen := int(len(decodedHash))

	rounds, err := strconv.ParseInt(deserialized.Params["i"].(string), 10, 32)
	if err != nil {
		return false, err
	}

	salt, err := hex.DecodeString(deserialized.Salt)
	if err != nil {
		return false, err
	}

	hashFunc := strings.Replace(deserialized.ID, "pbkdf2", "", 1)

	var verifyHash []byte

	switch hashFunc {
	case "sha1":
		verifyHash = pbkdf2.Key([]byte(plainPassword), salt, int(rounds), keyLen, sha1.New)
	case "sha256":
		verifyHash = pbkdf2.Key([]byte(plainPassword), salt, int(rounds), keyLen, sha256.New)
	case "sha224":
		verifyHash = pbkdf2.Key([]byte(plainPassword), salt, int(rounds), keyLen, sha256.New224)
	case "sha512":
		verifyHash = pbkdf2.Key([]byte(plainPassword), salt, int(rounds), keyLen, sha512.New)
	case "sha384":
		verifyHash = pbkdf2.Key([]byte(plainPassword), salt, int(rounds), keyLen, sha512.New384)
	case "md5":
		verifyHash = pbkdf2.Key([]byte(plainPassword), salt, int(rounds), keyLen, md5.New)
	default:
		return false, ErrUnexpectedHasherInstance
	}

	if subtle.ConstantTimeCompare(decodedHash, verifyHash) == 1 {
		return true, nil
	}
	return false, nil
}
