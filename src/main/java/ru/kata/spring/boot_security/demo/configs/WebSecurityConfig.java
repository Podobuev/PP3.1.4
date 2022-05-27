package ru.kata.spring.boot_security.demo.configs;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.boot.autoconfigure.security.oauth2.resource.PrincipalExtractor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.web.authentication.rememberme.InMemoryTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import ru.kata.spring.boot_security.demo.model.User;
import ru.kata.spring.boot_security.demo.repository.UserRepo;
import ru.kata.spring.boot_security.demo.service.UserService;

import javax.sql.DataSource;
import java.security.Principal;

@Configuration
@EnableWebSecurity
@ComponentScan(basePackages = "ru")
@EnableOAuth2Client
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {


    private UserService userService;

    private SuccessUserHandler successUserHandler;

    private BCryptPasswordEncoder bCryptPasswordEncoder;

    private DataSource dataSource;

    @Autowired
    public WebSecurityConfig(UserService userService, SuccessUserHandler successUserHandler, BCryptPasswordEncoder bCryptPasswordEncoder, DataSource dataSource) {
        this.userService = userService;
        this.successUserHandler = successUserHandler;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.dataSource = dataSource;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf()
                .disable()
                .authorizeRequests()
                .antMatchers("/registration", "/", "/login").permitAll()
                .antMatchers("/admin").hasRole("ADMIN")
                .antMatchers("/delete/**").hasRole("ADMIN")
                .antMatchers("/user/**").hasAnyRole("USER")
                .anyRequest().authenticated()
                .and()
                .formLogin().successHandler(successUserHandler)
//                .loginPage("/login")
                .permitAll()
                .and()
                .logout()
                .permitAll();


        http
                .authorizeRequests()
                .and()
                .rememberMe()
                .tokenRepository(this.persistentTokenRepository())
                .tokenValiditySeconds(1 * 24 * 60 * 60);

    }



    @Autowired
    protected void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userService).passwordEncoder(bCryptPasswordEncoder);
    }


    @Bean
    public PersistentTokenRepository persistentTokenRepository() {
        InMemoryTokenRepositoryImpl memory = new InMemoryTokenRepositoryImpl();
        return memory;
    }

    @Bean
    public PrincipalExtractor principalExtractor(UserRepo userRepo) {
        return map -> {
            return new User();
        };
    }




}