package routes

import (
	"encoding/json"
	"net/http"

	models "../models"
	util "../utils"
)

func getInicioHandler(w http.ResponseWriter, req *http.Request) {
	http.Error(w, "No estas autorizado", http.StatusInternalServerError)
	return
}

func entityRegisterHandler(w http.ResponseWriter, req *http.Request) {
	util.PrintLog("Registrando entidad...")
	var certs util.Certificados_Servidores
	// Get the JSON body and decode into credentials
	err := json.NewDecoder(req.Body).Decode(&certs)
	if err != nil {
		util.PrintErrorLog(err)
		// If the structure of the body is wrong, return an HTTP error
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	//INSERTAMOS CERTIFICADOS
	jsonReturn := util.JSON_Return{}
	result := models.InsertarEntidad(certs)
	if result == true {
		jsonReturn.Result = "OK"
	} else {
		jsonReturn.Error = "Error insertando la entidad"
	}
	//Devolvemos respuesta
	js, err := json.Marshal(jsonReturn)
	if err != nil {
		util.PrintErrorLog(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(js)
}

func entityCheckHandler(w http.ResponseWriter, req *http.Request) {
	var certs util.Certificados_Servidores
	// Get the JSON body and decode into credentials
	err := json.NewDecoder(req.Body).Decode(&certs)
	if err != nil {
		util.PrintErrorLog(err)
		// If the structure of the body is wrong, return an HTTP error
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	//COMPROBAMOS SI EXISTEN CERTIFICADOS PARA LA IP
	jsonReturn := util.JSON_Return{}
	result := models.ComprobarEntidad(certs)
	if result == true {
		jsonReturn.Result = "YES"
	} else {
		jsonReturn.Result = "NO"
	}

	//Devolvemos respuesta
	js, err := json.Marshal(jsonReturn)
	if err != nil {
		util.PrintErrorLog(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(js)
}
