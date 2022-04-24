function newUser() {

    let newFirstName = document.getElementById('newFirstName');
    let newLastName = document.getElementById('newLastName');
    let newEmail = document.getElementById('newEmail');
    let newAge = document.getElementById('newAge');
    let newPassword = document.getElementById('newPassword');

    let tableUsers = document.getElementById("tableUsers")

    let select = document.getElementById('newRoles')

    let new_Roles = []
    for (let i = 0; i < select.length; i++) {
        let option = select.options[i]
        if (option.selected) {
            new_Roles.push(option.value)

        }
    }


    fetch('http://localhost:8080/registration', {
        method: 'POST',
        body: JSON.stringify({
            firstName: newFirstName.value,
            lastName: newLastName.value,
            email: newEmail.value,
            age: newAge.value,
            password: newPassword.value,
            newRol: new_Roles
        }),
        headers: {"Content-type": "application/json; charset=UTF-8"}
    })
        .then(response => response.json())
        .then(user => {
            console.log(user.firstName)

            let r = "";
            let i = "";
            let x = user.roles;

            for (i in x) {

                r += user.roles[i].role.replace("ROLE_", "") + " ";

            }


            $('#usersTable tr:last').after('<tr id=' + user.id + '>' +
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

        })

}