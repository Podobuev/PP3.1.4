package ru.kata.spring.boot_security.demo.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import ru.kata.spring.boot_security.demo.model.User;

import java.nio.file.attribute.UserPrincipalNotFoundException;

public interface UserRepo extends JpaRepository<User, Long> {

    User findUserByEmail(String email) throws UsernameNotFoundException;
    User findUserById(Long id);
}
