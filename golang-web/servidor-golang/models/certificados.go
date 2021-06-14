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
	"strconv"
	"syscall"
	"time"

	util "../utils"
	"golang.org/x/crypto/ssh/terminal"
)

var ac_key []byte

func LoadEntityKey() bool {
	fmt.Print("Introduce contraseña: ")

	bytePassword := []byte("abcd1234!")
	/*bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return false
	}*/
	//password := string(bytePassword)
	//fmt.Println(password) //TEMP
	fmt.Println("")
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

func PruebaFirmaAC() bool {

	certAC, err := ioutil.ReadFile("./certificates/AC_cert.pem")
	if err != nil {
		fmt.Println("Firma AC: NOT OK FALTA CERTIFICADO AC")
		log.Fatal(err)
		return false
	}

	certEntidad, err := ioutil.ReadFile("./certificates/entidad_cert.pem")
	if err != nil {
		fmt.Println("Firma AC: NOT OK FALTA CERTIFICADO ENTIDAD")
		log.Fatal(err)
		return false
	}

	certEntidadFirmado, err := ioutil.ReadFile("./certificates/entidad_cert_firmado.bin")
	if err != nil {
		fmt.Println("Firma AC: NOT OK FALTA CERTIFICADO ENTIDAD FIRMADO")
		log.Fatal(err)
		return false
	}

	//PRUEBA DE VERIFICACIÓN
	certPublicKey := util.CertToPublicKey(certAC)
	result := util.Verificar(certEntidad, certEntidadFirmado, certPublicKey)
	if result == true {
		fmt.Println("Firma AC: OK")
		return true
	} else {
		fmt.Println("Firma AC: NOT OK")
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

func CreateUserCertificate(user_id int, identificationHash string) bool {
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
			CommonName:    identificationHash,
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

	certPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})

	certPEMBytes := certPEM.Bytes()
	certPrivKeyPEMBytes := certPrivKeyPEM.Bytes()

	//Recuperamos la clave pública del usuario
	userPairKeys, err := GetUserPublicKey(strconv.Itoa(user_id))
	if err != nil {
		return false
	}

	//Recuperamos la clave pública maestra
	masterPairKeys, err := GetPublicMasterKey()
	if err != nil {
		return false
	}

	//Ciframos la clave privada con AES
	AESkeyDatos := util.AEScreateKey()
	privCertCifrado, _ := util.AESencrypt(AESkeyDatos, string(certPrivKeyPEMBytes))
	userPublicKey := util.RSABytesToPublicKey(userPairKeys.PublicKey)
	masterPublicKey := util.RSABytesToPublicKey(masterPairKeys.PublicKey)

	//Pasamos la clave a base 64
	AESkeyBase64String := string(util.Base64Encode(AESkeyDatos))

	//Ciframos la clave AES usada con nuestra clave pública
	claveAEScifrada := util.RSAEncryptOAEP(AESkeyBase64String, *userPublicKey)
	claveMaestraAEScifrada := util.RSAEncryptOAEP(AESkeyBase64String, *masterPublicKey)

	result, err := InsertUserCertificates(user_id, util.Certificados_Servidores{Cert: certPEMBytes, Key: []byte(privCertCifrado)}, claveAEScifrada, claveMaestraAEScifrada)
	if err != nil {
		return false
	} else {
		return result
	}
}

func CreateEntityCertificate() bool {
	if util.FileExists("certificates/entidad_cert.pem") && util.FileExists("certificates/ciphered_key.bin") {
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
	fmt.Println("")
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
	/*keyCert, err := ioutil.ReadFile("certificates/ciphered_key.bin")
	if err != nil {
		log.Fatal(err)
		util.PrintErrorLog(err)
	}*/

	var certificados util.Certificados_Servidores
	certificados.IP_Servidor = "https://localhost:5001"
	certificados.Cert = enCert
	//certificados.Key = keyCert

	//Enviamos peticion
	client := GetTLSClient()
	locJson, err := json.Marshal(certificados)
	response, err := client.Post(AC_URL+"/entity/check", "application/json", bytes.NewBuffer(locJson))
	if response != nil {
		var result util.JSON_Return
		json.NewDecoder(response.Body).Decode(&result)
		if err != nil {
			util.PrintErrorLog(err)
		}
		util.PrintErrorLog(err)
		//SI NO EXISTE REGISTRAMOS EL CERTIFICADO
		if result.Result == "NO" {
			locJson, err = json.Marshal(certificados)
			response, err = client.Post(AC_URL+"/entity/register", "application/json", bytes.NewBuffer(locJson))
			if response != nil {
				var result util.Certificados_Servidores
				json.NewDecoder(response.Body).Decode(&result)
				if err != nil {
					util.PrintErrorLog(err)
				}
				if result.Code.Result == "OK" {
					fmt.Println("Registrar certificado en AC: REGISTRADO CORRECTAMENTE, OK")
					firmado := util.WriteFile("certificates/entidad_cert_firmado.bin", result.Cert)
					if firmado {
						fmt.Println("Registrar certificado en AC: RECUPERAR CERTIFICADO FIRMADO, OK")
						return true
					} else {
						fmt.Println("Registrar certificado en AC: RECUPERAR CERTIFICADO FIRMADO, ERROR")
						return false
					}
				} else {
					fmt.Println("Registrar certificado en AC: " + result.Code.Error)
					return false
				}
			}
			fmt.Println("Registrar certificado en AC: ERROR EN PETICION")
			return false
		} else {
			fmt.Println("Registrar certificado en AC: YA EXISTE, OK")
			return true
		}
	}
	fmt.Println("Registrar certificado en AC: AC NO OPERATIVA")
	return false
}

func LoadACCert() bool {
	if util.FileExists("certificates/AC_cert.pem") {
		fmt.Println("Cargar certificado de la AC: Ya estaba cargado, OK")
		return true
	} else {
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
		client := GetTLSClient()
		response, err := client.Get(AC_URL + "/cert")
		if response != nil {
			var result util.Certificados_Servidores
			json.NewDecoder(response.Body).Decode(&result)
			if err != nil {
				util.PrintErrorLog(err)
			}
			if result.Code.Result == "OK" {
				firmado := util.WriteFile("certificates/AC_cert.pem", result.Cert)
				if firmado {
					fmt.Println("Cargar certificado de la AC: RECUPERADO, OK")
					return true
				} else {
					fmt.Println("Registrar certificado en AC: NO RECUPERADO, ERROR")
					return false
				}
			} else {
				fmt.Println("Cargar certificado de la AC: " + result.Code.Error)
				return false
			}
		}
		fmt.Println("Cargar certificado de la AC: ERROR EN PETICIÓN")
		return false
	}
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

//CERTS

func InsertUserCertificates(user_id int, pairKeys util.Certificados_Servidores, clave string, clave_maestra string) (result bool, err error) {
	//INSERT
	_, err = db.Exec(`INSERT INTO usuarios_certificados (usuario_id, public_cert, private_cert, clave, clave_maestra) VALUES (?, ?, ?, ?, ?)`, user_id,
		pairKeys.Cert, pairKeys.Key, clave, clave_maestra)
	if err == nil {
		return true, nil
	} else {
		fmt.Println(err)
		util.PrintErrorLog(err)
	}
	return false, nil
}

//GET ENTITIES LIST

func GetEntitiesList() util.Listado_Entidades {
	var result util.Listado_Entidades
	result.Result = false
	file, _ := os.Open("config/config.json")
	defer file.Close()
	decoder := json.NewDecoder(file)
	configuration := util.Configuration{}
	err := decoder.Decode(&configuration)
	if err != nil {
		util.PrintErrorLog(err)
		return result
	}
	AC_URL := []string{configuration.AC_IP}[0]
	client := GetTLSClient()
	response, err := client.Get(AC_URL + "/entity/list")
	if response != nil {
		json.NewDecoder(response.Body).Decode(&result)
		if err != nil {
			util.PrintErrorLog(err)
		}
		result.Result = true
		return result
	}
	return result
}
