package passwordEncryptor

import "crypto/rand"

const defaultSaltLen = 256
const defaultIterations = 10000
const defaultKeyLen = 512

func GenerateSalt(length int) string {
	const alphanum = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	salt := make([]byte, length)
	rand.Read(salt)
	for key, val := range salt {
		salt[key] = alphanum[val%byte(len(alphanum))]
	}
	return string(salt)
}
