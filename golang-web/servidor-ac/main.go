package main

import (
	log "./lib/logs"
	models "./models"
	routes "./routes"
)

func main() {
	PUERTO := "7000"
	log.PrintLog("Servicio iniciado")
	models.CreateDB()
	routes.LoadRouter(PUERTO)
}
