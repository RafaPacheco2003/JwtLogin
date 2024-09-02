package com.jwt.login.jwt_login.User;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRespositorio extends JpaRepository<User,Integer> {
    Optional<User> findByUsername(String username); //Buscar datos por username
}
