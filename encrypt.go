package passwordEncryptor

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"

	"hash"

	"crypto/sha256"

	"golang.org/x/crypto/pbkdf2"
)

type options struct {
	saltLen      int
	iterations   int
	keyLen       int
	hashFunction func() hash.Hash
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

// EncryptPassword takes in a raw password as an argument, and returns its generated salt and encoded password,
// with default options, unless a set of custom ones are provided.
func EncryptPassword(rawPwd string, options ...interface{}) (string, string) {
	if len(options) == 0 {
		salt := generateSalt(defaultSaltLen)
		encodedPwd := pbkdf2.Key([]byte(rawPwd), salt, defaultIterations, defaultKeyLen, sha512.New)
		return string(salt), hex.EncodeToString(encodedPwd)
	}
	salt := generateSalt(options[0].(int))
	var hashFunction func() hash.Hash
	if options[3].(string) == "sha256" {
		hashFunction = sha256.New
	} else {
		hashFunction = sha512.New
	}
	encodedPwd := pbkdf2.Key([]byte(rawPwd), salt, options[1].(int), options[2].(int), hashFunction)
	return string(salt), hex.EncodeToString(encodedPwd)
}

// VerifyPassword takes three arguments, the raw password, its generated salt, and the encoded password,
// and returns a boolean value determining whether the password is the correct one or not, verifying with
// default options, unless a set of custom ones are provided.
func VerifyPassword(rawPwd string, salt string, encodedPwd string) bool {
	return encodedPwd == hex.EncodeToString(pbkdf2.Key([]byte(rawPwd), []byte(salt), defaultIterations, defaultKeyLen, sha512.New))
}
