package models

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"

	util "../utils"
)

func Firmar() bool {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		fmt.Printf("rsa.GenerateKey: %v\n", err)
		return false
	}

	message := "Hello World!"
	messageBytes := bytes.NewBufferString(message)
	hash := sha512.New()
	hash.Write(messageBytes.Bytes())
	digest := hash.Sum(nil)

	fmt.Printf("messageBytes: %v\n", messageBytes)
	fmt.Printf("hash: %V\n", hash)
	fmt.Printf("digest: %v\n", digest)

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA512, digest)
	if err != nil {
		fmt.Printf("rsa.SignPKCS1v15 error: %v\n", err)
		return false
	}

	fmt.Printf("signature: %v\n", signature)

	err = rsa.VerifyPKCS1v15(&privateKey.PublicKey, crypto.SHA512, digest, signature)
	if err != nil {
		fmt.Printf("rsa.VerifyPKCS1v15 error: %V\n", err)
		return false
	}

	fmt.Println("Signature good!")
	return true
}

func Verificar() bool {

	return true
}

func WriteFile(name string, bytes []byte) bool {
	// Open a new file for writing only
	file, err := os.OpenFile(
		name,
		os.O_WRONLY|os.O_TRUNC|os.O_CREATE,
		0666,
	)
	if err != nil {
		util.PrintErrorLog(err)
		return false
	}
	defer file.Close()

	// Write bytes to file
	_, err = file.Write(bytes)
	if err != nil {
		util.PrintErrorLog(err)
		return false
	}
	return true
}

func CrearCertificadoAC() bool {
	//filename is the path to the json config file
	file, _ := os.Open("config/config.json")
	defer file.Close()
	decoder := json.NewDecoder(file)
	configuration := util.Configuration{}
	err := decoder.Decode(&configuration)
	if err != nil {
		util.PrintErrorLog(err)
		return false
	}

	//First we’ll start off by creating our CA certificate. This is what we’ll use to sign other certificates that we create:
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{configuration.Organization},
			Country:       []string{configuration.Country},
			Province:      []string{configuration.Province},
			Locality:      []string{configuration.Locality},
			StreetAddress: []string{configuration.StreetAddress},
			PostalCode:    []string{configuration.PostalCode},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	//The IsCA field set to true will indicate that this is our CA certificate.
	//From here, we need to generate a public and private key for the certificate:
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		util.PrintErrorLog(err)
		return false
	}
	//And then we’ll generate the certificate:
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		util.PrintErrorLog(err)
		return false
	}
	//Now in caBytes we have our generated certificate, which we can PEM encode for later use:
	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	caPEMBytes := caPEM.Bytes()
	WriteFile("certificates/AC_cert.pem", caPEMBytes)

	caPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})
	caPrivKeyPEMBytes := caPrivKeyPEM.Bytes()
	WriteFile("certificates/AC_key.pem", caPrivKeyPEMBytes)

	fmt.Println("Crear certificado de la AC OK")
	util.PrintLog("Crear certificado de la AC OK")
	return true
}
