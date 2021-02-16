package routes

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"

	util "../utils"
)

type Page struct {
	Title string
	Body  string
}

func LoadRouter(port string) {

	//STATIC RESOURCES
	http.HandleFunc("/inicio", getInicioHandler)
	http.HandleFunc("/entity/register", entityRegisterHandler)
	http.HandleFunc("/entity/check", entityCheckHandler)
	http.HandleFunc("/cert", getACCertHandler)

	if port == "" {
		port = "7001"
	}
	// Create a CA certificate pool and add cert.pem to it
	caCert, err := ioutil.ReadFile("cert.pem")
	if err != nil {
		util.PrintErrorLog(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Create the TLS Config with the CA pool and enable Client certificate validation
	tlsConfig := &tls.Config{
		ClientCAs:  caCertPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}
	tlsConfig.BuildNameToCertificate()

	// Create a Server instance to listen on port 8443 with the TLS config
	server := &http.Server{
		Addr:      ":" + port,
		TLSConfig: tlsConfig,
	}
	fmt.Println("Servidor escuchando en el puerto ", port)

	//log.Fatal(server.ListenAndServeTLS("cert.pem", "key.pem"))
	err = server.ListenAndServeTLS("cert.pem", "key.pem")
	if err != nil {
		util.PrintErrorLog(err)
	}
}
