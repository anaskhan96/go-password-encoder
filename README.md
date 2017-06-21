# go-password-encryptor

This package in Go provides functions to encrypt a raw password (example, during registration on a site), and later verify it (example, while logging in to the site).

Functions available:
```go
func EncryptPassword(string, *Options) (string, string) // takes the raw password along with options, returns generated salt and hex encoded encrypted password
func VerifyPassword(string, string, string, *Options) bool // takes the raw password, the generated salt, and encoded password with options, and returns true or false
```

The `Options` struct is used to enable custom options:
```go
type Options struct {
	SaltLen      int
	Iterations   int
	KeyLen       int
	HashFunction func() hash.Hash
}
```
Passing `nil` as the last argument resorts to using the default options. The default options are as follows:
* Length of generated `salt` for the user is `256`
* Iteration count in [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2) function is `10000`
* Length of encoded key in [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2) function is `512`
* Hash algorithm used is `sha512`

Hover over to [Usage](#usage) for a complete example.

### Installation

```bash
go get github.com/anaskhan96/go-password-encryptor
```

Run `go test` in the package's directory to run tests.

### Usage

Following is an example depicting the usage of this package:

```go
package main

import (
	"crypto/md5"
	"fmt"
	"github.com/anaskhan96/go-password-encryptor"
)

func main() {
	// Using the default options
	salt, encodedPwd := passwordEncryptor.EncryptPassword("generic password", nil)
	check := passwordEncryptor.VerifyPassword("generic password", salt, encodedPwd, nil)
	fmt.Println(check) // true

	// Using custom options
	options := &passwordEncryptor.Options{10, 10000, 50, md5.New}
	salt, encodedPwd = passwordEncryptor.EncryptPassword("generic password", options)
	check = passwordEncryptor.VerifyPassword("generic password", salt, encodedPwd, options)
	fmt.Println(check) // true
}

```

### Related
* [node-password-encrypter](https://github.com/giovanniRodighiero/node-password-encrypter)
