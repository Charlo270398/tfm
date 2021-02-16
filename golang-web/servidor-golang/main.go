package main

import (
	models "./models"
	routes "./routes"
	util "./utils"
)

func main() {
	PUERTO := "5001"
	util.PrintLog("Servicio iniciado")
	models.LoadRoles()
	models.CreateDB()
	models.CreateEntityCertificate()
	models.RegisterEntityCertificate()
	models.LoadEntityKey()
	models.PruebaFirmar()
	models.LoadACCert()
	routes.LoadRouter(PUERTO)
}
