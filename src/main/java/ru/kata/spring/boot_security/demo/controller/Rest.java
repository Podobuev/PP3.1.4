package ru.kata.spring.boot_security.demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import ru.kata.spring.boot_security.demo.model.Role;
import ru.kata.spring.boot_security.demo.model.User;
import ru.kata.spring.boot_security.demo.repository.RoleRepo;
import ru.kata.spring.boot_security.demo.service.UserService;

import java.security.Principal;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@RestController
@ComponentScan(basePackages = "demo")
public class Rest {

    private UserService userService;
    private RoleRepo roleRepo;

    public Rest(UserService userService, RoleRepo roleRepo) {
        this.userService = userService;
        this.roleRepo = roleRepo;
    }

    @PostMapping(value = "/registration")
    public ResponseEntity<User> addUser (@RequestBody User user){

        userService.saveUser(user);

        return ResponseEntity.ok().body(user);
    }

    @GetMapping(value = "/info")
    public ResponseEntity<User> getUser(Principal principal) {
        User user = userService.findUserByEmail(principal.getName());
        return user != null ? new ResponseEntity<>(user, HttpStatus.OK)
                : new ResponseEntity<>(HttpStatus.NOT_FOUND);
    }

    @GetMapping(value = "/listUsers")
    public ResponseEntity<List<User>> getAllUsers() {
        final List<User> users = userService.getAllUsers();

        return users != null && !users.isEmpty() ? new ResponseEntity<>(users, HttpStatus.OK)
                : new ResponseEntity<> (HttpStatus.NOT_FOUND);
    }


    @GetMapping("/users/{id}")
    public ResponseEntity<User> getUserById(@PathVariable long id) {
        User user = userService.findUserById(id);

        return (user != null)
                ? new ResponseEntity<>(user, HttpStatus.OK)
                : new ResponseEntity<>(HttpStatus.NOT_FOUND);
    }

    @PutMapping(value = "/admin/edit")
    public ResponseEntity<?> updateUser(@RequestBody User user) {

        userService.editUser(user);
        return ResponseEntity.ok().body(user);
    }


    @DeleteMapping(value = "/admin/delete")
    public ResponseEntity<?> deleteUser(@RequestBody User user) {
        userService.deleteUser(user.getId());
        System.out.println(user);

        return new ResponseEntity<>(HttpStatus.OK);
    }
}


