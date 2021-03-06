function init () {
    deleteBreadcrumb();
    addLinkBreadcrumb('Usuario', '/user/menu');
    addLinkBreadcrumb('Medico', '/user/doctor');
    addLinkBreadcrumb('Citas pendientes', '/user/doctor/citas/list');
    loadTable(citasList);
    modalBorrar = document.querySelector("#borrarCitaIdModal");
    modalBorrar.addEventListener("click", deleteCita, false);
}

var SELECTED_CITA_ID;

function loadTable(cList){
    if(!cList || cList.length < 1){
        document.querySelector("#alert").textContent = "No hay ninguna cita pendiente";
        document.querySelector("#alert").classList.replace("alert-success", "alert-danger");
        document.querySelector("#alert").classList.remove('invisible');
    }
    cList.forEach(cita => {
        addRow(cita);
    });
}

function addRow(cita){
    let tr = document.createElement('tr');
    let fecha = document.createElement('td');
    let nombrePaciente = document.createElement('td');
    let tipo = document.createElement('td');
    let cancelacion = document.createElement('td');

    let deleteButton = document.createElement('button');
    deleteButton.setAttribute("data-toggle", "modal");
    deleteButton.setAttribute("data-target", "#borradoModal");
    deleteButton.classList = "btn btn-danger";
    deleteButton.type = "button";
    deleteButton.textContent = "Cancelar cita";
    deleteButton.addEventListener("click", selectDeleteCita, false);

    let pasarConsultaButton = document.createElement('button');
    pasarConsultaButton.classList = "btn btn-primary";
    pasarConsultaButton.type = "button";
    pasarConsultaButton.textContent = "Pasar consulta";
    pasarConsultaButton.addEventListener("click", pasarConsulta, false);

    cancelacion.append(deleteButton);
    cancelacion.append(pasarConsultaButton);
    fecha.textContent = cita.dia + "-" + cita.mes + "-" + cita.anyo + " a las " + cita.hora + ":00";
    nombrePaciente.textContent = cita.Historial.nombrePaciente + " " + cita.Historial.apellidosPaciente;
    tipo.textContent = cita.tipo;
    tr.append(fecha);
    tr.append(nombrePaciente);
    tr.append(tipo);
    tr.append(cancelacion);
    tr.setAttribute("id", cita.id);
    //Añadimos fila a la tabla
    document.querySelector(`#tablaCitas`).querySelector('tbody').append(tr);
}
function selectDeleteCita(event){
    SELECTED_CITA_ID = event.target.closest("tr").getAttribute("id");
}

function pasarConsulta(event){
    window.location.href = "/user/doctor/citas?citaId=" + event.target.closest("tr").getAttribute("id");
}

function deleteCita(event){
    deleteCitaREST(SELECTED_CITA_ID);
}

document.addEventListener('DOMContentLoaded',init,false);