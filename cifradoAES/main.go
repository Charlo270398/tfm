package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"
)

func main() {
	log.Print("File encryption example")

	log.Print("Enter filepath: ")
	var filePath string
	// Taking input from user
	fmt.Scanln(&filePath)

	plaintext, err := ioutil.ReadFile(filePath)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Print("Enter Password: ")
	bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return
	}
	password := string(bytePassword)
	fmt.Println(password) //TEMP

	// The key should be 16 bytes (AES-128), 24 bytes (AES-192) or
	// 32 bytes (AES-256)
	sha_256 := sha256.New()
	sha_256.Write(bytePassword)
	block, err := aes.NewCipher(sha_256.Sum(nil))
	if err != nil {
		log.Panic(err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Panic(err)
	}

	// Never use more than 2^32 random nonces with a given key
	// because of the risk of repeat.
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		log.Fatal(err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	// Save back to file
	err = ioutil.WriteFile("ciphered_key.bin", ciphertext, 0777)
	if err != nil {
		log.Panic(err)
	}
}
