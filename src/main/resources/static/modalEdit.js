function modalEdit(id) {
    fetch('http://localhost:8080/users/' + id)
        .then(response => response.json())
        .then(user => {

            console.log(user.firstName)

            let selAdmin = ""
            let selUser = ""
            let sel = ""

            let r = "";
            let i = "";


            for (i in user.roles) {

                sel = user.roles[i].role
                if (sel === 'ROLE_USER') {
                    selUser = 'selected'
                }
                if (sel === 'ROLE_ADMIN') {
                    selAdmin = 'selected'
                }


                r += user.roles[i].role.replace("ROLE_", "") + " ";
            }

            let modal = document.getElementById("modalWindow")
            modal.innerHTML = `
           
           <div class="modal fade" id="modalEdit" data-backdrop="static"
           data-keyboard="false" tabindex="-1" aria-labelledby="TitleModalLabel"
           aria-hidden="true">
                <div class="modal-dialog">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title" id="TitleModalLabel">Edit user</h5>
                            <button type="button" class="close" data-dismiss="modal"
                            aria-label="Close">
                                <span aria-hidden="true">&times;</span>
                            </button>
                </div>

                <div class="modal-body">
                    <div class="container-fluid">
                        <div class="row justify-content-center">
                            <div class="form-user col-md-8">
                                
                                   <div class="form-group text-center">
                                        <strong >Id</strong>
                                        <input type="text" class="form-control"
                                        value="${user.id}" id="id"
                                        readonly/>
                                   </div>
                                        
                                   <div class="form-group text-center">
                                        <strong >First name</strong>
                                        <input type="text" class="form-control"
                                        name="firstName" value="${user.firstName}"
                                        id="firstName"/>
                                   </div>
                                   
                                   <div class="form-group text-center">
                                        <strong >Last name</strong>
                                        <input type="text" class="form-control"
                                        name="lastName" value="${user.lastName}"
                                        id="lastName"/>
                                        </div>
                                        
                                   <div class="form-group">
                                        <div class="form-group text-center">
                                        <strong >Age</strong>
                                        <input type="text" class="form-control"
                                         name="age" value="${user.age}"
                                         id="age"/>
                                   </div>
                                   
                                   <div class="form-group text-center">
                                        <strong >Email</strong>
                                        <input type="text" class="form-control"
                                        name="email" value="${user.email}"
                                        id="email"/>
                                   </div>
                                   
                                   <div class="form-group text-center">
                                        <strong >Password</strong>
                                        <input type="text" class="form-control"
                                        name="password"
                                        
                                        id="password"/>
                                   </div>

                                    <div class="form-group text-center">
                                         <strong>Role</strong>
                                         <select id="rolesEdit"
                                         class="form-control form-control-sm"
                                         multiple size="2" required="required">
                                         <option value="ROLE_USER" label="USER" ${selUser}></option>
                                         <option value="ROLE_ADMIN" label="ADMIN" ${selAdmin}></option>
                                         </select
                                    </div>
                          </div>
                     </div>
                 </div>
           </div>
           <div class="modal-footer">
                <button type="button" class="btn btn-secondary"
                data-dismiss="modal">Close
                </button>
                <button class="btn btn-primary"
                data-dismiss="modal" onclick="editUser()">Edit </button>
                </div>
                </div>
                </div>
           </div>                                        
           
           `;

            $("#modalEdit").modal('show');


        });


}