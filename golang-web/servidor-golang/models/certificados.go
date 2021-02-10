package models

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"

	util "../utils"
)

func CreateEntityCertificate() bool {
	if util.FileExists("certificates/entidad_cert.pem") && util.FileExists("certificates/entidad_key.pem") {
		fmt.Println("Ya existe certificado para la entidad")
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
		util.WriteFile("certificates/entidad_key.pem", certPrivKeyPEMBytes)

		fmt.Println("Crear certificado de la entidad OK")
		util.PrintLog("Crear certificado de la entidad OK")
		return true
	}
}

func RegisterEntityCertificate() bool {
	//Recuperamos IP de la AC
	file, _ := os.Open("config/config.json")
	defer file.Close()
	decoder := json.NewDecoder(file)
	configuration := util.Configuration{}
	err := decoder.Decode(&configuration)
	if err != nil {
		util.PrintErrorLog(err)
		return false
	}
	AC_URL := []string{configuration.AC_IP}[0]
	//Cargamos los certificados
	enCert, err := ioutil.ReadFile("certificates/entidad_cert.pem")
	if err != nil {
		log.Fatal(err)
		util.PrintErrorLog(err)
	}
	keyCert, err := ioutil.ReadFile("certificates/entidad_key.pem")
	if err != nil {
		log.Fatal(err)
		util.PrintErrorLog(err)
	}

	var certificados util.Certificados_Servidores
	certificados.IP_Servidor = "https://localhost:5001"
	certificados.Cert = enCert
	certificados.Key = keyCert

	//Enviamos peticion
	client := GetTLSClient()
	locJson, err := json.Marshal(certificados)
	response, err := client.Post(AC_URL+"/entity/register", "application/json", bytes.NewBuffer(locJson))
	if response != nil {
		var result util.JSON_Return
		json.NewDecoder(response.Body).Decode(&result)
		if err != nil {
			util.PrintErrorLog(err)
		}
		util.PrintErrorLog(err)
	}
	locJson, err = json.Marshal(certificados)
	response, err = client.Post(AC_URL+"/entity/check", "application/json", bytes.NewBuffer(locJson))
	if response != nil {
		var result util.JSON_Return
		json.NewDecoder(response.Body).Decode(&result)
		if err != nil {
			util.PrintErrorLog(err)
		}
		util.PrintErrorLog(err)
		fmt.Println(result)
	}

	return false
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
