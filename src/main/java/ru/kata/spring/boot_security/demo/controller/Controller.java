package ru.kata.spring.boot_security.demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import ru.kata.spring.boot_security.demo.model.User;
import ru.kata.spring.boot_security.demo.service.UserService;

@org.springframework.stereotype.Controller
public class Controller {

    private UserService userService;

    @Autowired
    public Controller(UserService userService) {
        this.userService = userService;
    }

    @GetMapping(value = "/")
    public String login() {
        return "login";
    }

    @GetMapping(value = "/user")
    public String user() {
        return "userInfo";
    }

    @GetMapping(value = "/admin")
    public String admin() {
        return "admin";
    }



}
