package ru.kata.spring.boot_security.demo.postConstruct;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import ru.kata.spring.boot_security.demo.model.Role;
import ru.kata.spring.boot_security.demo.model.User;
import ru.kata.spring.boot_security.demo.service.RoleService;
import ru.kata.spring.boot_security.demo.service.UserService;

import javax.annotation.PostConstruct;
import java.util.HashSet;
import java.util.Set;

@Component
public class Admin {


    private final UserService userService;
    private RoleService roleService;

    @Autowired
    public Admin(UserService userService, RoleService roleService) {
        this.userService = userService;
        this.roleService = roleService;
    }

    @PostConstruct
    private void postConstruct() {

        if (roleService.findRoleByRole("ROLE_ADMIN") == null) {

            Role roleAdmin = new Role(1L, "ROLE_ADMIN");
            Role roleUser = new Role(2L, "ROLE_USER");

            roleService.saveRole(roleAdmin);
            roleService.saveRole(roleUser);

            Set<Role> roles = new HashSet<>();
            roles.add(roleAdmin);
            roles.add(roleUser);

            User admin = new User();
            admin.setId(1L);
            admin.setPassword("123");
            admin.setEmail("admin@test");
            admin.setRoles(roles);


            userService.postConstruct(admin);

        }
    }
}
