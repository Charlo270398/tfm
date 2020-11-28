package models

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"

	util "../utils"
)

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

func CreateEntityCertificate() bool {
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
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			Organization:  []string{configuration.Organization},
			Country:       []string{configuration.Country},
			Province:      []string{configuration.Province},
			Locality:      []string{configuration.Locality},
			StreetAddress: []string{configuration.StreetAddress},
			PostalCode:    []string{configuration.PostalCode},
		},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	//The IsCA field set to true will indicate that this is our CA certificate.
	//From here, we need to generate a public and private key for the certificate:
	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		util.PrintErrorLog(err)
		return false
	}
	//And then we’ll generate the certificate:
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, cert, &certPrivKey.PublicKey, certPrivKey)
	if err != nil {
		util.PrintErrorLog(err)
		return false
	}
	//Now in caBytes we have our generated certificate, which we can PEM encode for later use:
	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	certPEMBytes := certPEM.Bytes()
	WriteFile("certificates/entidad_cert.pem", certPEMBytes)

	certPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})
	certPrivKeyPEMBytes := certPrivKeyPEM.Bytes()
	WriteFile("certificates/entidad_key.pem", certPrivKeyPEMBytes)

	fmt.Println("Crear certificado de la entidad OK")
	util.PrintLog("Crear certificado de la entidad OK")
	return true
}
