

function newUser() {
    let form = window.formNewUser.newRoles;
    let new_Roles = [];
    let rolesList = document.createElement('ul');

    for (var i = 0; i < form.length; i++) {
        var option = form.options[i];
        let role = document.createElement('li');
        if (option.selected) {
            new_Roles[i] = option.value

            role.textContent = option.value.substring(5, 10) + " ";
            rolesList.appendChild(role);
        }
    }

    fetch('http://localhost:8080/registration', {
        method: 'POST',
        body: JSON.stringify({
            firstName: window.formNewUser.newFirstName.value,
            lastName: window.formNewUser.newLastName.value,
            age: window.formNewUser.newAge.value,
            email: window.formNewUser.newEmail.value,
            password: window.formNewUser.newPassword.value,
            newRol: new_Roles
        }),
        headers: {"Content-type": "application/json; charset=UTF-8"}
    })
        .then(response => response.json())
        .then(user => {

            $('#tableUsers:last').after('<tr id=' + user.id + '>' +
                '<td>' + user.id + '</td>' +
                '<td>' + window.formNewUser.newFirstName.value + '</td>' +
                '<td>' + window.formNewUser.newLastName.value + '</td>' +
                '<td>' + window.formNewUser.newAge.value + '</td>' +
                '<td>' + window.formNewUser.newEmail.value + '</td>' +
                '<td>' + 'Admin' + '</td>' +
                '<td> <button type="button" onclick="getModalEdit(' + user.id + ')" class="btn btn-primary btn-sm">Edit</button> </td>' +
                '<td> <button type="button" onclick="getModalDelete(' + user.id + ')" class="btn btn-danger btn-sm">Delete</button> </td>' +
                '</tr>');

            window.formNewUser.newFirstName.value = "";
            window.formNewUser.newLastName.value = "";
            window.formNewUser.newAge.value = "";
            window.formNewUser.newEmail.value = "";
            window.formNewUser.newPassword.value = "";
            window.formNewUser.newRoles.value = "";

            $('.nav-tabs a[href="#users_table"]').tab('show');
        });


}




let r = "";
let i = "";
let x = user.roles;

for (i in x) {
    r += user.roles[i].role.replace("ROLE_", "") + " ";
}

tableUsers.insertRow(-1).innerHTML = `
                <td> ${user.id} </td>
                <td> ${user.firstName} </td>
                <td> ${user.lastName} </td>
                <td> ${user.age} </td>
                <td> ${user.email} </td>
                <td> ${r} </td>
                <td> <button type="button" onclick="modalEdit(${user.id})" class="btn btn-info"> Edit </button> </td>
                <td> <button type="button" onclick="modalDelete(${user.id})" class="btn btn-danger"> Delete </button>  </td>`;


$('.nav-tabs a[href="#tableUsers"]').tab('show');





