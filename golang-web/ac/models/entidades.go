package models

import (
	"fmt"

	util "../utils"
)

func InsertarEntidad(entidad util.Certificados_Servidores) bool {
	//INSERT
	_, err := db.Exec(`INSERT INTO claves_entidades (server_ip, public_key) VALUES (?, ?)`, entidad.IP_Servidor, entidad.Cert)
	if err == nil {
		return true
	} else {
		fmt.Println(err)
		util.PrintErrorLog(err)
	}
	return false
}

func ComprobarEntidad(entidad util.Certificados_Servidores) bool {
	row, err := db.Query(`SELECT server_ip FROM claves_entidades WHERE server_ip = '` + entidad.IP_Servidor + `'`) // check err
	if err == nil {
		defer row.Close()
		row.Next()
		var IP string
		row.Scan(&IP)
		if IP == entidad.IP_Servidor {
			return true
		}
		return false
	} else {
		fmt.Println(err)
		util.PrintErrorLog(err)
	}
	return false
}
