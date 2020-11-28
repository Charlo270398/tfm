package routes

import (
	"net/http"
)

func getInicioHandler(w http.ResponseWriter, req *http.Request) {
	http.Error(w, "No estas autorizado", http.StatusInternalServerError)
	return
}
