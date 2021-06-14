package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"time"
)

func genCert(template, parent *x509.Certificate, publicKey *rsa.PublicKey, privateKey *rsa.PrivateKey) (*x509.Certificate, []byte) {
	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, privateKey)
	if err != nil {
		panic("Failed to create certificate:" + err.Error())
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		panic("Failed to parse certificate:" + err.Error())
	}

	b := pem.Block{Type: "CERTIFICATE", Bytes: certBytes}
	certPEM := pem.EncodeToMemory(&b)

	return cert, certPEM
}

func GenCARoot() (*x509.Certificate, []byte, *rsa.PrivateKey) {
	if _, err := os.Stat("someFile"); err == nil {
		//read PEM and cert from file
	}

	var rootTemplate = x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:      []string{"SE"},
			Organization: []string{"Company Co."},
			CommonName:   "Root CA",
		},
		NotBefore:             time.Now().Add(-10 * time.Second),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	rootCert, rootPEM := genCert(&rootTemplate, &rootTemplate, &priv.PublicKey, priv)

	WriteFile("AC_cert.pem", []byte(rootPEM))
	return rootCert, rootPEM, priv
}

func GenDCA(RootCert *x509.Certificate, RootKey *rsa.PrivateKey) (*x509.Certificate, []byte, *rsa.PrivateKey) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	certPEM, err := ioutil.ReadFile("./AC_cert.pem")
	block, _ := pem.Decode(certPEM)
	if block == nil {
		panic("failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("failed to parse certificate: " + err.Error())
	}

	/*var DCATemplate = x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:      []string{"SE"},
			Organization: []string{"Company Co."},
			CommonName:   "DCA",
		},
		NotBefore:             time.Now().Add(-10 * time.Second),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        false,
		MaxPathLen:            1,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}*/

	DCACert, DCAPEM := genCert(cert, RootCert, &priv.PublicKey, RootKey)
	return DCACert, DCAPEM, priv
}

func GenServerCert(DCACert *x509.Certificate, DCAKey *rsa.PrivateKey) (*x509.Certificate, []byte, *rsa.PrivateKey) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	certPEM, err := ioutil.ReadFile("./entidad_cert.pem")
	block, _ := pem.Decode(certPEM)
	if block == nil {
		panic("failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("failed to parse certificate: " + err.Error())
	}

	/*var ServerTemplate = x509.Certificate{
		SerialNumber:   big.NewInt(1),
		NotBefore:      time.Now().Add(-10 * time.Second),
		NotAfter:       time.Now().AddDate(10, 0, 0),
		KeyUsage:       x509.KeyUsageCRLSign,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:           false,
		MaxPathLenZero: true,
		IPAddresses:    []net.IP{net.ParseIP("127.0.0.1")},
	}*/

	ServerCert, ServerPEM := genCert(cert, DCACert, &priv.PublicKey, DCAKey)
	return ServerCert, ServerPEM, priv

}

func verifyDCA(root, dca *x509.Certificate) {
	roots := x509.NewCertPool()
	roots.AddCert(root)
	opts := x509.VerifyOptions{
		Roots: roots,
	}

	if _, err := dca.Verify(opts); err != nil {
		panic("failed to verify certificate: " + err.Error())
	}
	fmt.Println("DCA verified")
}

func verifyLow(root, DCA, child *x509.Certificate) {
	roots := x509.NewCertPool()
	inter := x509.NewCertPool()
	roots.AddCert(root)
	inter.AddCert(DCA)
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
	}

	if _, err := child.Verify(opts); err != nil {
		panic("failed to verify certificate: " + err.Error())
	}
	fmt.Println("Low Verified")
}

func WriteFile(name string, bytes []byte) bool {
	// Open a new file for writing only
	file, err := os.OpenFile(
		name,
		os.O_WRONLY|os.O_TRUNC|os.O_CREATE,
		0666,
	)
	if err != nil {
		return false
	}
	defer file.Close()

	// Write bytes to file
	_, err = file.Write(bytes)
	if err != nil {
		return false
	}
	return true
}

func main() {
	rootCert, rootCertPEM, rootKey := GenCARoot()
	fmt.Println("rootCert\n", string(rootCertPEM))
	DCACert, DCACertPEM, DCAKey := GenDCA(rootCert, rootKey)
	fmt.Println("DCACert\n", string(DCACertPEM))
	verifyDCA(rootCert, DCACert)
	ServerCert, ServerPEM, _ := GenServerCert(DCACert, DCAKey)
	fmt.Println("ServerPEM\n", string(ServerPEM))
	verifyLow(rootCert, DCACert, ServerCert)
}
