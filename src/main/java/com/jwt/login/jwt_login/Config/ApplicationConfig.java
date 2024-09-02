package com.jwt.login.jwt_login.Config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.jwt.login.jwt_login.User.UserRespositorio;

import lombok.RequiredArgsConstructor;


@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {


    private final UserRespositorio userRespositorio;


    /*Is used to encode and verify a password
     * 
     * Cuando un usuario se registra, su contraseña se codifica usando este 
     * PasswordEncoder antes de almacenarse en la base de datos.
     * Durante el inicio de sesión, la contraseña ingresada se codifica 
     * de la misma manera y se compara con la versión codificada almacenada en la base de datos.
     */
    @Bean
    public PasswordEncoder passwordEncoder(){

        return new BCryptPasswordEncoder();
    }

    /*this bean is used to load the user details from the userRepositorio using thed username
     *  se utiliza para recuperar la información del usuario desde la base de datos para su autenticación,
     *  y se usa principalmente en el DaoAuthenticationProvider.
     */
    @Bean
    public UserDetailsService userDetailService() {
        return username -> userRespositorio.findByUsername(username)
            .orElseThrow(()
                -> new UsernameNotFoundException("User not fournd"));
    }



    /*Interface to  manage authentication
     *
     *  se utiliza para autenticar un Authentication
     *  (como el nombre de usuario y la contraseña) 
     * y devolver un objeto autenticado si la autenticación tiene éxito.
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) 
    throws Exception{
        return configuration.getAuthenticationManager();
    }

    /*this interface is used to define with autenticate a user by the credentials
     * 
     * DaoAuthenticationProvider es una implementación de 
     * AuthenticationProvider que usa UserDetailsService para 
     * recuperar detalles del usuario desde una base de datos.
     * 
     * Se establece el UserDetailsService y el PasswordEncoder en el DaoAuthenticationProvider 
     * para que pueda manejar la autenticación utilizando los detalles del usuario recuperados y 
     * codificar/verificar la contraseña.
     */
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailService());
        authenticationProvider.setPasswordEncoder(passwordEncoder());
    return authenticationProvider;
}


}
