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
	models.CrearCertificadoAC()
	models.Firmar()
	routes.LoadRouter(PUERTO)
}
