package com.jwt.login.jwt_login.Auth;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.jwt.login.jwt_login.Jwt.JwtService;
import com.jwt.login.jwt_login.User.Role;
import com.jwt.login.jwt_login.User.User;
import com.jwt.login.jwt_login.User.UserRespositorio;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRespositorio userRepositorio;

    private final JwtService jwtService;// Generate and validate tokens. Is used to create token the autentication for a
                                        // users

    private final PasswordEncoder passwordEncoder; // Provides methods to encrypt and verify passwords. It is used to
                                                   // ensure that passwordsare stored securely

    private final AuthenticationManager authenticationManager;// Maneja el proceso de autenticación de usuarios,
                                                              // verificando las credenciales proporcionadas.

    public AuthResponse login(LoginRequest request) {
        // Autenticación del usuario con las credenciales proporcionadas
        authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));

        // Recupera los detalles del usuario desde el repositorio
        UserDetails user = userRepositorio.findByUsername(request.getUsername()).orElseThrow();

        // Genera un token JWT para el usuario autenticado
        String token = jwtService.getToken(user);

        // Devuelve una respuesta de autenticación que incluye el token
        return AuthResponse.builder()
                .token(token)
                .build();
    }

    public AuthResponse register(RegisterRequest request) {
        // Crear el usuario con la información proporcionada en la solicitud
        User user = User.builder()
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword())) // Asegúrate de cifrar la contraseña
                .firstname(request.getFirstname())
                .lastname(request.getLastname()) // Acceso al campo lastname
                .country(request.getCountry())
                .role(Role.USER)
                .build();

        // Guardar el usuario en el repositorio
        userRepositorio.save(user);

        // Devuelve una respuesta de autenticación que incluye el token
        return AuthResponse.builder()
                .token(jwtService.getToken(user)) // Obtener el token
                .build();
    }

}
