showListUsers();

let tableUsers = document.getElementById("tableUsers")

function showListUsers() {
    fetch('http://localhost:8080/listUsers')
        .then(response => response.json())
        .then(user => {


            let i = "";
            let j = "";
            let x = "";

            for (i in user) {
                let r = "";
                x = user[i].roles;

                for (j in user[i].roles) {
                    r += x[j].role.replace("ROLE_", "") + " ";
                }

                tableUsers.innerHTML += `<tr id="${user[i].id}"> 
                    <td> ${user[i].id} </td>
                    <td> ${user[i].firstName} </td>
                    <td> ${user[i].lastName} </td>
                    <td> ${user[i].age} </td>
                    <td> ${user[i].email} </td>
                    <td> ${r} </td>
                
                    <td>       
                        <button type="button" onclick="modalEdit(${user[i].id})" class="btn btn-info"> Edit </button>
                    </td>
                
                    <td>       
                        <button type="button" onclick="modalDelete(${user[i].id})" class="btn btn-danger"> Delete </button> 
                    </td>
        
                    </tr>`;

            }

        });
}



