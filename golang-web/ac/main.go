package main

import (
	"encoding/json"
	"fmt"
	"os"

	models "./models"
	routes "./routes"
	util "./utils"
)

func main() {
	//CARGAMOS FICHERO DE CONFIGURACION
	file, _ := os.Open("config/config.json")
	defer file.Close()
	decoder := json.NewDecoder(file)
	configuration := util.Configuration{}
	err := decoder.Decode(&configuration)
	if err != nil {
		util.PrintErrorLog(err)
	}
	fmt.Println("Servicio iniciado")
	models.CreateDB()
	models.CrearCertificadoAC()
	models.LoadACKey()
	models.PruebaFirmar()
	routes.LoadRouter(configuration.Port)
}
