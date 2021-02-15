package models

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"syscall"
	"time"

	util "../utils"
	"golang.org/x/crypto/ssh/terminal"
)

var ac_key []byte

func LoadACKey() bool {
	fmt.Print("Introduce contraseña: ")

	bytePassword := []byte("abcd1234!")
	/*bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return false
	}*/
	//password := string(bytePassword)
	//fmt.Println(password) //TEMP

	cipheredkey, err := ioutil.ReadFile("./certificates/ciphered_key.bin")
	if err != nil {
		log.Fatal(err)
		return false
	}

	sha_256 := sha256.New()
	sha_256.Write(bytePassword)
	block, err := aes.NewCipher(sha_256.Sum(nil))
	if err != nil {
		log.Panic(err)
		return false
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Panic(err)
		return false
	}

	nonce := cipheredkey[:gcm.NonceSize()]
	cipheredkey = cipheredkey[gcm.NonceSize():]
	plaintextKey, err := gcm.Open(nil, nonce, cipheredkey, nil)
	if err != nil {
		log.Panic(err)
	}

	ac_key = plaintextKey
	//fmt.Println(string(plaintextKey))

	return true
}

func PruebaFirmar() bool {
	messageBytes := bytes.NewBufferString("Prueba Firma")
	firma := Firmar(messageBytes.Bytes())
	verificado := Verificar(messageBytes.Bytes(), firma)
	if verificado == true {
		fmt.Println("Firma OK")
		return true
	} else {
		fmt.Println("Firma NOT OK")
		return false
	}
}

func Firmar(data []byte) []byte {

	privateKey := util.RSABytesToPrivateKey(ac_key)
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

func Verificar(data []byte, signature []byte) bool {
	privateKey := util.RSABytesToPrivateKey(ac_key)
	hash := sha512.New()
	hash.Write(data)
	digest := hash.Sum(nil)

	err := rsa.VerifyPKCS1v15(&privateKey.PublicKey, crypto.SHA512, digest, signature)
	if err != nil {
		fmt.Printf("rsa.VerifyPKCS1v15 error: %V\n", err)
		return false
	}
	return true
}

func CrearCertificadoAC() bool {
	if util.FileExists("certificates/entidad_cert.pem") && util.FileExists("certificates/ciphered_key.bin") {
		fmt.Println("Ya existe certificado para Autoridad Certificadora")
		return true
	} else {
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
		util.WriteFile("certificates/entidad_cert.pem", certPEMBytes)

		certPrivKeyPEM := new(bytes.Buffer)
		pem.Encode(certPrivKeyPEM, &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
		})
		certPrivKeyPEMBytes := certPrivKeyPEM.Bytes()
		//util.WriteFile("certificates/entidad_key.pem", certPrivKeyPEMBytes)

		resultCipherKey := CipherKey(certPrivKeyPEMBytes)

		if resultCipherKey == true {
			fmt.Println("Crear certificado de la entidad OK")
			util.PrintLog("Crear certificado de la entidad OK")
			return true
		} else {
			fmt.Println("Crear certificado de la entidad NOT OK")
			util.PrintLog("Crear certificado de la entidad NOT OK")
			return false
		}
	}
}

func CipherKey(key_file []byte) bool {
	fmt.Print("Introduce contraseña: ")
	bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return false
	}
	// The key should be 16 bytes (AES-128), 24 bytes (AES-192) or
	// 32 bytes (AES-256)
	sha_256 := sha256.New()
	sha_256.Write(bytePassword)
	block, err := aes.NewCipher(sha_256.Sum(nil))
	if err != nil {
		log.Panic(err)
		return false
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Panic(err)
		return false
	}

	// Never use more than 2^32 random nonces with a given key
	// because of the risk of repeat.
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		log.Fatal(err)
		return false
	}

	ciphertext := gcm.Seal(nonce, nonce, key_file, nil)
	// Save back to file
	err = ioutil.WriteFile("certificates/ciphered_key.bin", ciphertext, 0777)
	if err != nil {
		log.Panic(err)
		return false
	}
	return true
}

func GetTLSClient() *http.Client {
	//Certificado
	// Read the key pair to create certificate
	cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		log.Fatal(err)
		util.PrintErrorLog(err)
	}

	// Create a CA certificate pool and add cert.pem to it
	caCert, err := ioutil.ReadFile("cert.pem")
	if err != nil {
		log.Fatal(err)
		util.PrintErrorLog(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Create a HTTPS client and supply the created CA pool and certificate
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      caCertPool,
				Certificates: []tls.Certificate{cert},
			},
		},
	}
	return client
}
