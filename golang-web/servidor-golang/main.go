package main

import (
	"fmt"

	models "./models"
	routes "./routes"
	util "./utils"
)

func main() {
	PUERTO := "5001"
	util.PrintLog("Servicio iniciado")
	models.LoadRoles()
	models.CreateDB()
	adminOK := false
	if models.ExisteAdmin() == true {
		adminOK = models.LoginAdmin()
	} else {
		adminOK = models.CrearAdmin()
	}
	if adminOK == true {
		fmt.Println("Autenticacion OK")
		models.CreateEntityCertificate()
		registerEntityOK := models.RegisterEntityCertificate()
		if registerEntityOK == true {
			models.LoadEntityKey()
			models.PruebaFirmar()
			models.LoadACCert()
			routes.LoadRouter(PUERTO)
		}
	} else {
		fmt.Println("Error autenticando al usuario Admin")
	}
}
