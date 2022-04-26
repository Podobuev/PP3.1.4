package ru.kata.spring.boot_security.demo.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.kata.spring.boot_security.demo.model.Role;
import ru.kata.spring.boot_security.demo.model.User;
import ru.kata.spring.boot_security.demo.repository.UserRepo;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Service
public class UserServiceImp implements UserService {


    private UserRepo userRepo;
    private RoleService roleService;
    private BCryptPasswordEncoder bCryptPasswordEncoder;


    @Autowired
    public UserServiceImp(UserRepo userRepo, RoleService roleService, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.userRepo = userRepo;
        this.roleService = roleService;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    public UserServiceImp() {
    }

    @Override
    @Transactional
    public void postConstruct(User user) {


        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        userRepo.save(user);


    }

    @Override
    @Transactional
    public void saveUser(User user) {

        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));

        Set<Role> roles = new HashSet<>();
        for (String r : user.getNewRol()) {
            roles.add(roleService.findRoleByRole(r));
        }
        user.setRoles(roles);

        userRepo.save(user);
    }

    @Override
    public void deleteUser(Long id) {
        userRepo.deleteById(id);
    }

    @Override
    public User getUser(Long id) {
        return userRepo.getById(id);
    }

    @Override
    public List<User> getAllUsers() {
        return userRepo.findAll();
    }

    @Override
    public User findUserByEmail(String email) {
        return userRepo.findUserByEmail(email);
    }

    @Override
    public User findUserById(Long id) {
        User user = userRepo.getById(id);
        System.out.println(user);
        return user;
    }


    @Override
    @Transactional
    public void editUser(User user) {

        Set<Role> roles = new HashSet<>();
        for (String r : user.getNewRol()) {
            roles.add(roleService.findRoleByRole(r));
        }
        user.setRoles(roles);

        if (user.getPassword().equals(userRepo.findUserById(user.getId()).getPassword())) {
            userRepo.save(user);
        } else if (user.getPassword().equals("")) {
            user.setPassword(userRepo.findUserById(user.getId()).getPassword());
            userRepo.save(user);
        } else {
            saveUser(user);
        }
    }



    @Override
    public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {
        return userRepo.findUserByEmail(userName);
    }
}
