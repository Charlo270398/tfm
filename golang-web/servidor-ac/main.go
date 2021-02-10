package main

import (
	"fmt"

	models "./models"
	routes "./routes"
)

func main() {

	PUERTO := "7000"
	fmt.Println("Servicio iniciado")
	models.CreateDB()
	models.LoadACKey()
	models.CrearCertificadoAC()
	models.PruebaFirmar()
	routes.LoadRouter(PUERTO)
}
