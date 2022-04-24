function deleteUser() {

    let deleteId = document.getElementById('deleteId')
    let deleteFirstName = document.getElementById('deleteFirstName');
    let deleteLastName = document.getElementById('deleteLastName');
    let deleteEmail = document.getElementById('deleteEmail');
    let deleteAge = document.getElementById('deleteAge');
    let deletePassword = document.getElementById('deletePassword');


    let select = document.getElementById('deleteRoles')

    let deleteRoles = []
    for (let i = 0; i < select.length; i++) {
        let option = select.options[i];
        if (option.selected) {
            deleteRoles.push(option.value)
        }
    }

    fetch('/admin/delete', {
        method: 'DELETE',
        body: JSON.stringify({
            id: deleteId.value,
            firstName: deleteFirstName.value,
            lastName: deleteLastName.value,
            email: deleteEmail.value,
            age: deleteAge.value,
            password: deletePassword.value,
            newRol: deleteRoles
        }),
        headers: {"Content-type": "application/json; charset=UTF-8"}
    })

    let tableUsers = document.getElementById("tableUsers")


    let deleteIndex = document.getElementById(deleteId.value).rowIndex
    console.log(deleteIndex)


    tableUsers.deleteRow(deleteIndex-1)

    $('.nav-tabs a[href="#usersTable"]').tab('show');
}


// function deleteUser(id) {
//     fetch('http://localhost:8080/admin/delete' + id, {
//         method: 'DELETE',
//         headers: {"Content-type": "application/json; charset=UTF-8"}
//     })
//         .then(response => {
//             $('#' + id).remove();
//         });
// }