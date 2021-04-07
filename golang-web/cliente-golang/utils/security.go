package utils

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
)

func RSAGenerateKeys() *rsa.PrivateKey {
	// Generate RSA keys Of 2048 Buts
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		PrintErrorLog(err)
	}
	return privKey
}

func RSAEncryptOAEP(secretMessage string, pubkey rsa.PublicKey) string {
	label := []byte("OAEP Encrypted")
	// crypto/rand.Reader is a good source of entropy for randomizing the
	// encryption function.
	rng := rand.Reader
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rng, &pubkey, []byte(secretMessage), label)
	if err != nil {
		PrintErrorLog(err)
		return ""
	}
	return base64.StdEncoding.EncodeToString(ciphertext)
}

func RSADecryptOAEP(cipherText string, privKey rsa.PrivateKey) string {
	ct, _ := base64.StdEncoding.DecodeString(cipherText)
	label := []byte("OAEP Encrypted")

	// crypto/rand.Reader is a good source of entropy for blinding the RSA
	// operation.
	rng := rand.Reader
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rng, &privKey, ct, label)
	if err != nil {
		PrintErrorLog(err)
		return ""
	}

	return string(plaintext)
}

// PrivateKeyToBytes private key to bytes
func RSAPrivateKeyToBytes(priv *rsa.PrivateKey) []byte {
	privBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		},
	)

	return privBytes
}

// PublicKeyToBytes public key to bytes
func RSAPublicKeyToBytes(pub *rsa.PublicKey) []byte {
	pubASN1, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		PrintErrorLog(err)
	}

	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})

	return pubBytes
}

// StringToPrivateKey bytes to private key
func RSAStringToPrivateKey(privString string) *rsa.PrivateKey {
	priv := []byte(privString)
	block, _ := pem.Decode(priv)
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	var err error
	if enc {
		b, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			PrintErrorLog(err)
		}
	}
	key, err := x509.ParsePKCS1PrivateKey(b)
	if err != nil {
		PrintErrorLog(err)
	}
	return key
}

// BytesToPrivateKey bytes to private key
func RSABytesToPrivateKey(priv []byte) *rsa.PrivateKey {
	block, _ := pem.Decode(priv)
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	var err error
	if enc {
		b, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			PrintErrorLog(err)
		}
	}
	key, err := x509.ParsePKCS1PrivateKey(b)
	if err != nil {
		PrintErrorLog(err)
	}
	return key
}

// BytesToPublicKey bytes to public key
func RSABytesToPublicKey(pub []byte) *rsa.PublicKey {
	block, _ := pem.Decode(pub)
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	var err error
	if enc {
		b, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			PrintErrorLog(err)
		}
	}
	ifc, err := x509.ParsePKIXPublicKey(b)
	if err != nil {
		PrintErrorLog(err)
	}
	key, ok := ifc.(*rsa.PublicKey)
	if !ok {
		PrintLog("NOT OK")
	}
	return key
}

//AES

func AEScreateKey() []byte {
	genkey := make([]byte, 32) //32-BYTES; 256 bits
	_, err := rand.Read(genkey)
	if err != nil {
		log.Fatalf("Failed to read new random key: %s", err)
	}
	return genkey
}

func AESencrypt(key []byte, message string) (encmess string, err error) {
	plainText := []byte(message)

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	//IV needs to be unique, but doesn't have to be secure.
	//It's common to put it at the beginning of the ciphertext.
	cipherText := make([]byte, aes.BlockSize+len(plainText))
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)

	//returns to base64 encoded string
	encmess = base64.URLEncoding.EncodeToString(cipherText)
	return
}

func AESdecrypt(key []byte, securemess string) (decodedmess string, err error) {
	cipherText, err := base64.URLEncoding.DecodeString(securemess)
	if err != nil {
		return
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	if len(cipherText) < aes.BlockSize {
		err = errors.New("Ciphertext block size is too short!")
		return
	}

	//IV needs to be unique, but doesn't have to be secure.
	//It's common to put it at the beginning of the ciphertext.
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(cipherText, cipherText)

	decodedmess = string(cipherText)
	return
}

//BASE 64

func Base64Encode(message []byte) []byte {
	b := make([]byte, base64.StdEncoding.EncodedLen(len(message)))
	base64.StdEncoding.Encode(b, message)
	return b
}

func Base64Decode(message []byte) []byte {
	var l int
	b := make([]byte, base64.StdEncoding.DecodedLen(len(message)))
	l, err := base64.StdEncoding.Decode(b, message)
	if err != nil {
		return nil
	}
	return b[:l]
}

//FIRMA

func Firmar(data []byte, privateKey *rsa.PrivateKey) []byte {
	hash := sha512.New()
	hash.Write(data)
	digest := hash.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA512, digest)
	if err != nil {
		fmt.Printf("rsa.SignPKCS1v15 error: %v\n", err)
		return nil
	}
	return signature

}

func Verificar(data []byte, signature []byte, publicKey *rsa.PublicKey) bool {
	hash := sha512.New()
	hash.Write(data)
	digest := hash.Sum(nil)
	err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA512, digest, signature)
	if err != nil {
		fmt.Printf("rsa.VerifyPKCS1v15 error: %V\n", err)
		return false
	}
	return true
}

func CertToPublicKey(certificado []byte) *rsa.PublicKey {
	block, _ := pem.Decode(certificado)
	var cert *x509.Certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	rsaPublicKey := cert.PublicKey.(*rsa.PublicKey)

	return rsaPublicKey
}
