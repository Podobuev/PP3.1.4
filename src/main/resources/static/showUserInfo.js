showUserInfo();

let table = document.getElementById("userInfo")
let line = document.getElementById("upLine")
let mailLine = document.getElementById("mailLine")

function showUserInfo(user) {
    fetch('http://localhost:8080/info')
        .then(response => response.json())
        .then(user => {

            let r = "";
            let i = "";
            let x = user.roles;

            for (i in x) {
                r += user.roles[i].role.replace("ROLE_", "") + " ";
            }

            console.log(r)

            table.innerHTML = `<tr> 
                <td> ${user.id} </td>
                <td> ${user.firstName} </td>
                <td> ${user.lastName} </td>
                <td> ${user.age} </td>
                <td> ${user.email} </td>
                <td> ${r} </td>
                
                </tr>`;

            line.innerHTML = r;
            mailLine.innerHTML = user.email;

        });
}



