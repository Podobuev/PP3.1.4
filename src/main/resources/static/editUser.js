function editUser() {

    let id = document.getElementById('id')
    let firstName = document.getElementById('firstName');
    let lastName = document.getElementById('lastName');
    let email = document.getElementById('email');
    let age = document.getElementById('age');
    let password = document.getElementById('password');


    let select = document.getElementById('rolesEdit')

    let editRoles = []
    for (let i = 0; i < select.length; i++) {
        let option = select.options[i];
        if (option.selected) {
            editRoles.push(option.value)
        }
    }

    fetch('/admin/edit', {
        method: 'PUT',
        body: JSON.stringify({
            id: id.value,
            firstName: firstName.value,
            lastName: lastName.value,
            email: email.value,
            age: age.value,
            password: password.value,
            newRol: editRoles
        }),
        headers: {"Content-type": "application/json; charset=UTF-8"}
    })
        .then(response => response.json())
        .then(user => {

            let r = "";
            let i = "";
            let x = user.roles;

            for (i in x) {

                r += user.roles[i].role.replace("ROLE_", "") + " ";

            }


                $('#' + user.id).replaceWith('<tr id =' + user.id + '>' +
                    '<td>' + user.id + '</td>' +
                    '<td>' + user.firstName + '</td>' +
                    '<td>' + user.lastName + '</td>' +
                    '<td>' + user.age + '</td>' +
                    '<td>' + user.email + '</td>' +
                    '<td>' + r + '</td>' +
                    '<td> <button type="button" onclick="modalEdit(' + user.id + ')" class="btn btn-info"> Edit </button> </td>' +
                    '<td> <button type="button" onclick="modalDelete(' + user.id + ')" class="btn btn-danger"> Delete </button> </td>' + +
                    '</tr>');

            $('.nav-tabs a[href="#usersTable"]').tab('show');
            });
        }




