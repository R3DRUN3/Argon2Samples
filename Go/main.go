package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

type ArgonConfig struct {
	time    uint32
	memory  uint32
	threads uint8
	keyLen  uint32
}

func main() {
	config := &ArgonConfig{
		time:    2,
		memory:  64 * 1024,
		threads: 2,
		keyLen:  64,
	}
	fmt.Println("Insert a password to hash: ")
	var myPassword string
	fmt.Scanf("%s", &myPassword)
	hash, err := HashPassword(config, myPassword)
	if err != nil {
		panic(err)
	}
	fmt.Println("Argon2 hashed password: ", hash)

	for {
		fmt.Println("Insert a password to verify: ")
		var passwordToVerify string
		fmt.Scanf("%s", &passwordToVerify)
		match, err := VerifyPassword(passwordToVerify, hash)
		if !match || err != nil {
			fmt.Println("Not the Original Password ◉︵◉")
		} else {
			fmt.Println("Same Password !!! (◕‿◕) ")
		}
	}
}

// Hash a password (string) with Argon2
func HashPassword(c *ArgonConfig, password string) (string, error) {
	// Create the Salt
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, c.time, c.memory, c.threads, c.keyLen)
	// Base64 encode the salt and hashed password.
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)
	format := "$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s" //Argon2 Format
	full := fmt.Sprintf(format, argon2.Version, c.memory, c.time, c.threads, b64Salt, b64Hash)
	return full, nil
}

// Compare user input (password) to the hashed one to see if the are equal
func VerifyPassword(password, hash string) (bool, error) {
	parts := strings.Split(hash, "$")
	c := &ArgonConfig{}
	_, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &c.memory, &c.time, &c.threads)
	if err != nil {
		return false, err
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, err
	}
	decodedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, err
	}
	c.keyLen = uint32(len(decodedHash))
	comparisonHash := argon2.IDKey([]byte(password), salt, c.time, c.memory, c.threads, c.keyLen)
	return (subtle.ConstantTimeCompare(decodedHash, comparisonHash) == 1), nil
}
