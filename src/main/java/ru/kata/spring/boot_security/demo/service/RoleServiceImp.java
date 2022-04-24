package ru.kata.spring.boot_security.demo.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import ru.kata.spring.boot_security.demo.model.Role;
import ru.kata.spring.boot_security.demo.repository.RoleRepo;

import java.util.List;

@Service
public class RoleServiceImp implements RoleService {

    RoleRepo roleRepo;

    @Autowired
    public RoleServiceImp(RoleRepo roleRepo) {
        this.roleRepo = roleRepo;
    }

    @Override
    public Role findRoleByRole(String role) {
        return roleRepo.findRoleByRole(role);
    }

    @Override
    public List<Role> getAllRoles() {
        return roleRepo.findAll();
    }

    @Override
    public void saveRole(Role role) {
        roleRepo.save(role);
    }
}
