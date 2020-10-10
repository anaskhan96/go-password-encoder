# go-password-encoder
[![Build Status](https://travis-ci.org/anaskhan96/go-password-encoder.svg?branch=master)](https://travis-ci.org/anaskhan96/go-password-encoder)
[![GoDoc](https://godoc.org/github.com/anaskhan96/go-password-encoder?status.svg)](https://pkg.go.dev/github.com/anaskhan96/go-password-encoder)
[![Go Report Card](https://goreportcard.com/badge/github.com/anaskhan96/go-password-encoder)](https://goreportcard.com/report/github.com/anaskhan96/go-password-encoder)

This package in Go provides functions to encode a raw password (example, during registration on a site), and later verify it (example, while logging in to the site).

Functions available:
```go
func Encode(string, *Options) (string, string) {} // takes the raw password along with options, returns generated salt and hex encoded password
func Verify(string, string, string, *Options) bool {} // takes the raw password, the generated salt, and encoded password with options, and returns true or false
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
Passing `nil` as the last argument in either function resorts to using the default options. The default options are as follows:
* Length of generated `salt` for the user is `256`
* Iteration count in [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2) function is `10000`
* Length of encoded key in [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2) function is `512`
* Hash algorithm used is `sha512`

Hover over to [Usage](#usage) for a complete example.

### Installation

```bash
go get github.com/anaskhan96/go-password-encoder
```

Run `go test` in the package's directory to run tests.

### Usage

Following is an example depicting the usage of this package:

```go
package main

import (
	"crypto/md5"
	"fmt"
	"github.com/anaskhan96/go-password-encoder"
)

func main() {
	// Using the default options
	salt, encodedPwd := password.Encode("generic password", nil)
	check := password.Verify("generic password", salt, encodedPwd, nil)
	fmt.Println(check) // true

	// Using custom options
	options := &password.Options{10, 10000, 50, md5.New}
	salt, encodedPwd = password.Encode("generic password", options)
	check = password.Verify("generic password", salt, encodedPwd, options)
	fmt.Println(check) // true
}

```

### Related
* [node-password-encrypter](https://github.com/giovanniRodighiero/node-password-encrypter)
