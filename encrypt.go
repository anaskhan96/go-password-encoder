package passwordEncryptor

import (
	"crypto/rand"
	"crypto/sha512"

	"encoding/hex"

	"golang.org/x/crypto/pbkdf2"
)

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

// EncryptPassword takes in a raw password as an argument, and returns its generated salt and encoded password.
func EncryptPassword(rawPwd string) (string, string) {
	salt := generateSalt(defaultSaltLen)
	encodedPwd := pbkdf2.Key([]byte(rawPwd), salt, defaultIterations, defaultKeyLen, sha512.New)
	return string(salt), hex.EncodeToString(encodedPwd)
}
