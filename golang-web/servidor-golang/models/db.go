package models

import (
	"database/sql"
	"fmt"
	"log"

	"strconv"

	util "../utils"

	_ "github.com/go-sql-driver/mysql"
)

var db *sql.DB //variable db común a todos

func ConnectDB() {
	var err error
	db, err = sql.Open("mysql", "golang:@(127.0.0.1:3306)/tfm-golang-entidad1?parseTime=true")
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
	query(CLINICAS_TABLE)
	query(ESPECIALIDADES_TABLE)
	query(USUARIOS_TABLE)
	query(ROLES_TABLE)
	query(USERS_CLINICAS_TABLE)
	query(USERS_ESPECIALIDADES_TABLE)
	query(USERS_ROLES_TABLE)
	query(USERS_TOKENS_TABLE)
	query(USERS_PAIRKEYS_TABLE)
	query(USERS_MASTER_PAIRKEYS_TABLE)
	query(USERS_DNIHASHES_TABLE)
	query(EMPLEADOS_NOMBRES_TABLE)
	query(CITAS_TABLE)
	query(USERS_HISTORIAL_TABLE)
	query(USERS_PERMISOS_HISTORIAL_TABLE)
	query(USERS_ENTRADAS_HISTORIAL_TABLE)
	query(USERS_PERMISOS_ENTRADAS_HISTORIAL_TABLE)
	query(USERS_ANALITICAS_TABLE)
	query(USERS_PERMISOS_ANALITICAS_TABLE)
	query(TAGS_TABLE)
	query(ESTADISTICAS_ANALITICAS_TABLE)
	query(ESTADISTICAS_ANALITICAS_TAGS_TABLE)
	query(SOLICITAR_HISTORIAL_TABLE)
	query(SOLICITAR_HISTORIAL_TOTAL_TABLE)
	query(SOLICITAR_ENTRADAS_HISTORIAL_TABLE)
	query(SOLICITAR_ANALITICAS_HISTORIAL_TABLE)

	//SEEDERS
	//Roles
	query("INSERT IGNORE INTO roles (id,nombre,descripcion) VALUES (" + strconv.Itoa(Rol_paciente.Id) + ",'" + Rol_paciente.Nombre + "', '" + Rol_paciente.Descripcion + "');")
	query("INSERT IGNORE INTO roles (id,nombre,descripcion) VALUES (" + strconv.Itoa(Rol_enfermero.Id) + ",'" + Rol_enfermero.Nombre + "', '" + Rol_enfermero.Descripcion + "');")
	query("INSERT IGNORE INTO roles (id,nombre,descripcion) VALUES (" + strconv.Itoa(Rol_medico.Id) + ",'" + Rol_medico.Nombre + "', '" + Rol_medico.Descripcion + "');")
	query("INSERT IGNORE INTO roles (id,nombre,descripcion) VALUES (" + strconv.Itoa(Rol_administradorC.Id) + ",'" + Rol_administradorC.Nombre + "', '" + Rol_administradorC.Descripcion + "');")
	query("INSERT IGNORE INTO roles (id,nombre,descripcion) VALUES (" + strconv.Itoa(Rol_administradorG.Id) + ",'" + Rol_administradorG.Nombre + "', '" + Rol_administradorG.Descripcion + "');")
	query("INSERT IGNORE INTO roles (id,nombre,descripcion) VALUES (" + strconv.Itoa(Rol_emergencias.Id) + ",'" + Rol_emergencias.Nombre + "', '" + Rol_emergencias.Descripcion + "');")

	//Roles
	query("INSERT IGNORE INTO clinicas (id,nombre,direccion,telefono) VALUES (1,'Clínica Alicante', 'C/Noruega nº190', '965891433');")
	query("INSERT IGNORE INTO clinicas (id,nombre,direccion,telefono) VALUES (2,'Clínica Benidorm', 'Avda. Zamora nº11', '965891438');")
	query("INSERT IGNORE INTO clinicas (id,nombre,direccion,telefono) VALUES (3,'Clínica Elche', 'C/Palmeral nº13', '965891436');")

	//Especialidades
	query("INSERT IGNORE INTO especialidades (id,nombre) VALUES (1,'Dermatología');")
	query("INSERT IGNORE INTO especialidades (id,nombre) VALUES (2,'Pediatría');")
	query("INSERT IGNORE INTO especialidades (id,nombre) VALUES (3,'Oncología');")
	query("INSERT IGNORE INTO especialidades (id,nombre) VALUES (4,'Rehabilitación');")
	query("INSERT IGNORE INTO especialidades (id,nombre) VALUES (5,'Ginecología');")
	query("INSERT IGNORE INTO especialidades (id,nombre) VALUES (6,'Hematología');")
	query("INSERT IGNORE INTO especialidades (id,nombre) VALUES (7,'Psiquiatría');")

	//Tags
	query("INSERT IGNORE INTO tags (id,nombre) VALUES (1,'Obesidad');")
	query("INSERT IGNORE INTO tags (id,nombre) VALUES (2,'Taquicardia');")
	query("INSERT IGNORE INTO tags (id,nombre) VALUES (3,'Anorexia');")
	query("INSERT IGNORE INTO tags (id,nombre) VALUES (4,'Anemia');")
	query("INSERT IGNORE INTO tags (id,nombre) VALUES (5,'Hombre');")
	query("INSERT IGNORE INTO tags (id,nombre) VALUES (6,'Mujer');")

	fmt.Println("Database OK")
}

var CLINICAS_TABLE string = `
CREATE TABLE IF NOT EXISTS clinicas (
	id INT AUTO_INCREMENT,
	nombre VARCHAR(20) UNIQUE,
	direccion VARCHAR(50),
	telefono VARCHAR(16),
	PRIMARY KEY (id)
);`

var ESPECIALIDADES_TABLE string = `
CREATE TABLE IF NOT EXISTS especialidades (
	id INT AUTO_INCREMENT,
	nombre VARCHAR(30) UNIQUE,
	PRIMARY KEY (id)
);`

var USUARIOS_TABLE string = `
CREATE TABLE IF NOT EXISTS usuarios (
	id INT AUTO_INCREMENT,
	dni VARCHAR(36) UNIQUE,
	nombre VARCHAR(100) NOT NULL,
	apellidos VARCHAR(150) NOT NULL,
	email VARCHAR(100) UNIQUE,
	password VARCHAR(100) NOT NULL,
	created_at DATETIME,
	clave VARCHAR(344) NOT NULL,
	clave_maestra VARCHAR(344) NOT NULL,
	PRIMARY KEY (id)
);`

var ROLES_TABLE string = `
CREATE TABLE IF NOT EXISTS roles (
	id INT AUTO_INCREMENT,
	nombre VARCHAR(20) UNIQUE,
	descripcion VARCHAR(50),
	PRIMARY KEY (id)
);`

var TAGS_TABLE string = `
CREATE TABLE IF NOT EXISTS tags (
	id INT AUTO_INCREMENT,
	nombre VARCHAR(30) UNIQUE,
	PRIMARY KEY (id)
);`

//Relaciones

var USERS_CLINICAS_TABLE string = `
CREATE TABLE IF NOT EXISTS usuarios_clinicas (
	usuario_id INT,
	clinica_id INT,
	rol_id INT,
	PRIMARY KEY (usuario_id, clinica_id, rol_id),
	FOREIGN KEY(usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE,
	FOREIGN KEY(clinica_id) REFERENCES clinicas(id) ON DELETE CASCADE,
	FOREIGN KEY(rol_id) REFERENCES roles(id) ON DELETE CASCADE
);`

var USERS_ESPECIALIDADES_TABLE string = `
CREATE TABLE IF NOT EXISTS usuarios_especialidades (
	usuario_id INT,
	especialidad_id INT,
	PRIMARY KEY(usuario_id, especialidad_id),
	FOREIGN KEY(usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE,
	FOREIGN KEY(especialidad_id) REFERENCES especialidades(id) ON DELETE CASCADE
);`

var USERS_ROLES_TABLE string = `
CREATE TABLE IF NOT EXISTS usuarios_roles (
	usuario_id INT,
	rol_id INT,
	PRIMARY KEY (usuario_id, rol_id),
	FOREIGN KEY(usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE,
	FOREIGN KEY(rol_id) REFERENCES roles(id) ON DELETE CASCADE
);`

var USERS_TOKENS_TABLE string = `
CREATE TABLE IF NOT EXISTS usuarios_tokens (
	id INT AUTO_INCREMENT,
	usuario_id INT UNIQUE,
	token VARCHAR(156),
	fecha_expiracion DATETIME,
	PRIMARY KEY (id),
	FOREIGN KEY(usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
);`

var USERS_PAIRKEYS_TABLE string = `
CREATE TABLE IF NOT EXISTS usuarios_pairkeys (
	id INT AUTO_INCREMENT,
	usuario_id INT UNIQUE,
	public_key BLOB,
	private_key BLOB,
	PRIMARY KEY (id),
	FOREIGN KEY(usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
);`

var USERS_MASTER_PAIRKEYS_TABLE string = `
CREATE TABLE IF NOT EXISTS usuarios_master_pairkeys (
	id INT AUTO_INCREMENT,
	usuario_id INT UNIQUE,
	public_key BLOB,
	private_key BLOB,
	PRIMARY KEY (id),
	FOREIGN KEY(usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
);`

var USERS_DNIHASHES_TABLE string = `
CREATE TABLE IF NOT EXISTS usuarios_dnihashes(
	usuario_id INT,
	dni_hash VARCHAR(64),
	FOREIGN KEY(usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE,
	UNIQUE (dni_hash),
	PRIMARY KEY (usuario_id)
);`

var EMPLEADOS_NOMBRES_TABLE string = `
CREATE TABLE IF NOT EXISTS empleados_nombres (
	usuario_id INT,
	nombre VARCHAR(150) NOT NULL,
	FOREIGN KEY(usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE,
	PRIMARY KEY (usuario_id)
);`

var CITAS_TABLE string = `
CREATE TABLE IF NOT EXISTS citas (
	id INT AUTO_INCREMENT,
	medico_id INT,
	paciente_id INT,
	anyo INT,
	mes INT,
	dia INT,
	hora INT,
	tipo VARCHAR(30) NOT NULL, 
	FOREIGN KEY(medico_id) REFERENCES usuarios(id) ON DELETE CASCADE,
	FOREIGN KEY(paciente_id) REFERENCES usuarios(id) ON DELETE CASCADE,
	UNIQUE (medico_id, anyo, mes, dia, hora),
	PRIMARY KEY (id)
);`

var ESTADISTICAS_ANALITICAS_TABLE string = `
CREATE TABLE IF NOT EXISTS estadisticas_analiticas (
	id VARCHAR(36),
	leucocitos FLOAT,
	hematies FLOAT,
	plaquetas FLOAT,
	glucosa FLOAT,
	hierro FLOAT,
	PRIMARY KEY (id)
);`

var ESTADISTICAS_ANALITICAS_TAGS_TABLE string = `
CREATE TABLE IF NOT EXISTS estadisticas_analiticas_tags (
	analitica_id VARCHAR(36),
	tag_id INT,
	PRIMARY KEY (analitica_id, tag_id),
	FOREIGN KEY(tag_id) REFERENCES tags(id) ON DELETE CASCADE,
	FOREIGN KEY(analitica_id) REFERENCES estadisticas_analiticas(id) ON DELETE CASCADE
);`

//HISTORIAL

var USERS_HISTORIAL_TABLE string = `
CREATE TABLE IF NOT EXISTS usuarios_historial (
	id INT AUTO_INCREMENT,
	sexo varchar(100), 
	alergias varchar(500),
	usuario_id INT,
	ultima_actualizacion VARCHAR(200),
	clave VARCHAR(344) NOT NULL,
	clave_maestra VARCHAR(344) NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
);`

var USERS_ENTRADAS_HISTORIAL_TABLE string = `
CREATE TABLE IF NOT EXISTS usuarios_entradas_historial (
	id INT AUTO_INCREMENT,
	empleado_id INT,
	historial_id INT,
	tipo varchar(100), 
	motivo_consulta varchar(500), 
	juicio_diagnostico varchar(500),
	clave VARCHAR(344) NOT NULL,
	clave_maestra VARCHAR(344) NOT NULL,
	created_at VARCHAR(200),
	PRIMARY KEY (id),
	FOREIGN KEY(historial_id) REFERENCES usuarios_historial(id) ON DELETE CASCADE,
	FOREIGN KEY(empleado_id) REFERENCES usuarios(id) ON DELETE CASCADE
);`

var USERS_ANALITICAS_TABLE string = `
CREATE TABLE IF NOT EXISTS usuarios_analiticas (
	id INT AUTO_INCREMENT,
	empleado_id INT,
	historial_id INT,
	leucocitos VARCHAR(100),
	hematies VARCHAR(100),
	plaquetas VARCHAR(100),
	glucosa VARCHAR(100),
	hierro VARCHAR(100),
	created_at VARCHAR(200),
	clave VARCHAR(344) NOT NULL,
	clave_maestra VARCHAR(344) NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(historial_id) REFERENCES usuarios_historial(id) ON DELETE CASCADE,
	FOREIGN KEY(empleado_id) REFERENCES usuarios(id) ON DELETE CASCADE
);`

//PERMISOS-HISTORIAL

var USERS_PERMISOS_HISTORIAL_TABLE string = `
CREATE TABLE IF NOT EXISTS usuarios_permisos_historial (
	historial_id INT,
	empleado_id INT,
	clave VARCHAR(344) NOT NULL,
	PRIMARY KEY (historial_id, empleado_id),
	FOREIGN KEY(historial_id) REFERENCES usuarios_historial(id) ON DELETE CASCADE,
	FOREIGN KEY(empleado_id) REFERENCES usuarios(id) ON DELETE CASCADE
);`

var USERS_PERMISOS_ENTRADAS_HISTORIAL_TABLE string = `
CREATE TABLE IF NOT EXISTS usuarios_permisos_entradas_historial (
	entrada_id INT,
	empleado_id INT,
	clave VARCHAR(344) NOT NULL,
	PRIMARY KEY (entrada_id, empleado_id),
	FOREIGN KEY(entrada_id) REFERENCES usuarios_entradas_historial(id) ON DELETE CASCADE,
	FOREIGN KEY(empleado_id) REFERENCES usuarios(id) ON DELETE CASCADE
);`

var USERS_PERMISOS_ANALITICAS_TABLE string = `
CREATE TABLE IF NOT EXISTS usuarios_permisos_analiticas (
	analitica_id INT,
	empleado_id INT,
	clave VARCHAR(344) NOT NULL,
	PRIMARY KEY (analitica_id, empleado_id),
	FOREIGN KEY(analitica_id) REFERENCES usuarios_analiticas(id) ON DELETE CASCADE,
	FOREIGN KEY(empleado_id) REFERENCES usuarios(id) ON DELETE CASCADE
);`

//Solicitudes
var SOLICITAR_HISTORIAL_TABLE string = `
CREATE TABLE IF NOT EXISTS solicitar_historial (
	paciente_id INT,
	empleado_id INT,
	PRIMARY KEY (paciente_id, empleado_id),
	FOREIGN KEY(paciente_id) REFERENCES usuarios(id) ON DELETE CASCADE,
	FOREIGN KEY(empleado_id) REFERENCES usuarios(id) ON DELETE CASCADE
);`

var SOLICITAR_HISTORIAL_TOTAL_TABLE string = `
CREATE TABLE IF NOT EXISTS solicitar_historial_total (
	paciente_id INT,
	empleado_id INT,
	PRIMARY KEY (paciente_id, empleado_id),
	FOREIGN KEY(paciente_id) REFERENCES usuarios(id) ON DELETE CASCADE,
	FOREIGN KEY(empleado_id) REFERENCES usuarios(id) ON DELETE CASCADE
);`

var SOLICITAR_ENTRADAS_HISTORIAL_TABLE string = `
CREATE TABLE IF NOT EXISTS solicitar_entradas_historial (
	paciente_id INT,
	empleado_id INT,
	entrada_id INT,
	PRIMARY KEY (paciente_id, empleado_id, entrada_id),
	FOREIGN KEY(paciente_id) REFERENCES usuarios(id) ON DELETE CASCADE,
	FOREIGN KEY(empleado_id) REFERENCES usuarios(id) ON DELETE CASCADE,
	FOREIGN KEY(entrada_id) REFERENCES usuarios_entradas_historial(id) ON DELETE CASCADE
);`

var SOLICITAR_ANALITICAS_HISTORIAL_TABLE string = `
CREATE TABLE IF NOT EXISTS solicitar_analiticas (
	paciente_id INT,
	empleado_id INT,
	analitica_id INT,
	PRIMARY KEY (paciente_id, empleado_id, analitica_id),
	FOREIGN KEY(paciente_id) REFERENCES usuarios(id) ON DELETE CASCADE,
	FOREIGN KEY(empleado_id) REFERENCES usuarios(id) ON DELETE CASCADE,
	FOREIGN KEY(analitica_id) REFERENCES usuarios_analiticas(id) ON DELETE CASCADE
);`
