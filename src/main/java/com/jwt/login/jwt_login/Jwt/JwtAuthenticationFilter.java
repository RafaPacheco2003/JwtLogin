package com.jwt.login.jwt_login.Jwt;

import java.io.IOException;

import org.springframework.http.HttpHeaders;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.util.StringUtils;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    // Método para extraer el token JWT de la solicitud
    private String getTokenFromRequest(HttpServletRequest request) {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (StringUtils.hasText(authHeader) && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return null;
    }

    /*Extrae el Token: Llama a getTokenFromRequest para obtener el token JWT de la solicitud.
    Cargar Detalles del Usuario: Carga los detalles del usuario desde UserDetailsService.
    Verifica la Validez del Token: Comprueba si el token es válido para el usuario.
    Establece la Autenticación: Si el token es válido, crea un objeto UsernamePasswordAuthenticationToken y lo configura en el contexto de seguridad de Spring.
    Valida el Token: Si el token no es nulo, obtiene el nombre de usuario del token.
    Continúa con el Filtro: Permite que la solicitud continúe a través de la cadena de filtros. */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        // Extracts the JWT token from the request
        final String token = getTokenFromRequest(request);
        final String username;

        // If the token is null
        if (token == null) {
            filterChain.doFilter(request, response);
            return;
        }

        // Get the username of the token
        username = jwtService.getUsernameFromToken(token);

        // If the username is not empty and there is no prior authentication
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            // Load the user details
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            // Verify if the token is valid for the user
            if (jwtService.isTokenValid(token, userDetails)) {
                // Create an authentication token with the user's details and authorities
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                    userDetails,
                    null,
                    userDetails.getAuthorities()
                );

                // Add additional authentication details
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // Sets authentication to the security context
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }

        // Continúa con el siguiente filtro en la cadena
        filterChain.doFilter(request, response);
    }
}
