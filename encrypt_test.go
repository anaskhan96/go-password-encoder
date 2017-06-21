package passwordEncryptor

import (
	"encoding/hex"
	"reflect"
	"testing"
)

func TestEncryptPassword(t *testing.T) {
	salt, encoded := EncryptPassword("random string", nil)
	if !reflect.DeepEqual(len([]byte(salt)), defaultSaltLen) {
		t.Error("Received length of salt:", len([]byte(salt)), "Expected length of salt:", defaultSaltLen)
	}
	encodedBytes, err := hex.DecodeString(encoded)
	if err != nil {
		t.Error("Encrypted Password not hex encoded properly")
	}
	if !reflect.DeepEqual(len(encodedBytes), defaultKeyLen) {
		t.Error("Received length of password:", len(encodedBytes), "Expected length of password:", defaultKeyLen)
	}
}
