package com.jwt.login.jwt_login.Config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.jwt.login.jwt_login.Jwt.JwtAuthenticationFilter;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final AuthenticationProvider authProvider;

    /**
     * Configura la cadena de filtros de seguridad de Spring Security.
     * Establece las reglas de autorización, la política de creación de sesiones,
     * y añade el filtro de autenticación JWT.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
            .cors()  // Habilitar CORS (Cross-Origin Resource Sharing) si es necesario
            .and()
            .csrf(csrf -> csrf.disable())  // Deshabilitar CSRF (Cross-Site Request Forgery) ya que estamos usando JWT
            .authorizeHttpRequests(authRequest ->
                authRequest
                    .requestMatchers("/auth/**", "/login", "/register").permitAll()  // Permitir acceso sin autenticación a rutas específicas
                    .anyRequest().authenticated()  // Requerir autenticación para todas las demás solicitudes
            )
            .sessionManagement(sessionManager ->
                sessionManager.sessionCreationPolicy(SessionCreationPolicy.STATELESS)  // Configurar la política de sesiones como sin estado (stateless)
            )
            .authenticationProvider(authProvider)  // Configurar el proveedor de autenticación
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)  // Añadir el filtro JWT antes del filtro de autenticación por nombre de usuario y contraseña
            .build();
    }
}
