package passwordEncryptor

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"

	"hash"

	"golang.org/x/crypto/pbkdf2"
)

type Options struct {
	SaltLen      int
	Iterations   int
	KeyLen       int
	HashFunction func() hash.Hash
}

const defaultSaltLen = 256
const defaultIterations = 10000
const defaultKeyLen = 512

func generateSalt(length int) []byte {
	const alphanum = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	salt := make([]byte, length)
	rand.Read(salt)
	for key, val := range salt {
		salt[key] = alphanum[val%byte(len(alphanum))]
	}
	return salt
}

// EncryptPassword takes two arguments, a raw password, and a pointer to an Options struct.
// In order to use default options, pass `nil` as the second argument.
func EncryptPassword(rawPwd string, options *Options) (string, string) {
	if options == nil {
		salt := generateSalt(defaultSaltLen)
		encodedPwd := pbkdf2.Key([]byte(rawPwd), salt, defaultIterations, defaultKeyLen, sha512.New)
		return string(salt), hex.EncodeToString(encodedPwd)
	}
	salt := generateSalt(options.KeyLen)
	encodedPwd := pbkdf2.Key([]byte(rawPwd), salt, options.Iterations, options.KeyLen, options.HashFunction)
	return string(salt), hex.EncodeToString(encodedPwd)
}

// VerifyPassword takes three arguments, the raw password, its generated salt, and the encoded password,
// and returns a boolean value determining whether the password is the correct one or not, verifying with
// default options, unless a set of custom ones are provided.
func VerifyPassword(rawPwd string, salt string, encodedPwd string) bool {
	return encodedPwd == hex.EncodeToString(pbkdf2.Key([]byte(rawPwd), []byte(salt), defaultIterations, defaultKeyLen, sha512.New))
}
