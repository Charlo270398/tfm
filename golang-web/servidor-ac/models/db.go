package models

import (
	"database/sql"
	"fmt"
	"log"

	util "../utils"

	_ "github.com/go-sql-driver/mysql"
)

var db *sql.DB //variable db común a todos

func ConnectDB() {
	var err error
	db, err = sql.Open("mysql", "golang:@(127.0.0.1:3306)/tfm-golang-ac?parseTime=true")
	if err != nil {
		util.PrintErrorLog(err)
		log.Panic(err)
	}

	if err = db.Ping(); err != nil {
		util.PrintErrorLog(err)
		log.Panic(err)
	}
}
func query(query string) bool {

	// Executes the SQL query in our database. Check err to ensure there was no error.
	if _, err := db.Exec(query); err != nil {
		util.PrintErrorLog(err)
		return false
	}
	return true
}

func CreateDB() {
	ConnectDB()
	//CREATE TABLES
	query(CLAVES_ENTIDADES_TABLE)
	fmt.Println("Database OK")
}

var CLAVES_ENTIDADES_TABLE string = `
CREATE TABLE IF NOT EXISTS claves_entidades (
	id_entidad INT UNIQUE,
	public_key BLOB,
	PRIMARY KEY (id_entidad)
);`
