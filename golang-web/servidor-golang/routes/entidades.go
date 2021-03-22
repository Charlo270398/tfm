package routes

import (
	"encoding/json"
	"net/http"

	models "../models"
	util "../utils"
)


func GetListadoEntidades(w http.ResponseWriter, req *http.Request) {
	var userToken util.UserToken_JSON
	json.NewDecoder(req.Body).Decode(&userToken)

	//Comprobamos que el usuario esta autorizado y el token es correcto
	authorizedMedico, _ := models.GetAuthorizationbyUserId(userToken.UserId, userToken.Token, models.Rol_medico.Id)
	authorized := authorizedMedico
	if authorized == true {
		listadoEntidades := models.GetEntitiesList()
		js, err := json.Marshal(listadoEntidades)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		return
	}
	http.Error(w, "No estas autorizado", http.StatusInternalServerError)
	return
}