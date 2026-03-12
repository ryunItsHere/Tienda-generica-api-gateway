package com.tiendagenerica.api_gateway.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

@Component
public class AuthenticationFilter
        implements GlobalFilter, Ordered {

    @Autowired
    private JwtUtil jwtUtil;

    private static final List<String> RUTAS_PUBLICAS =
            List.of("/auth/login");

    private static final List<String> SOLO_ADMIN = List.of(
            "/productos/guardar",
            "/productos/actualizar",
            "/productos/eliminar",
            "/clientes/eliminar",
            "/usuarios/listar",
            "/usuarios/crear",
            "/usuarios/actualizar",
            "/usuarios/estado",
            "/ventas/listar",
            "/reportes",
            "/proveedor/createjson",
            "/proveedor/updatejson",
            "/proveedor/deletebyid"
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange,
                             GatewayFilterChain chain) {

        String path = exchange.getRequest()
                .getURI().getPath();

        if (esRutaPublica(path)) {
            return chain.filter(exchange);
        }

        String authHeader = exchange.getRequest()
                .getHeaders()
                .getFirst(HttpHeaders.AUTHORIZATION);

        if (authHeader == null
                || !authHeader.startsWith("Bearer ")) {
            return rechazar(exchange,
                    HttpStatus.UNAUTHORIZED,
                    "Token no proporcionado");
        }

        String token = authHeader.substring(7);

        if (!jwtUtil.validarToken(token)) {
            return rechazar(exchange,
                    HttpStatus.UNAUTHORIZED,
                    "Token inválido o expirado");
        }

        String rol = jwtUtil.extraerRol(token);

        if (esSoloAdmin(path) && !"ADMIN".equals(rol)) {
            return rechazar(exchange,
                    HttpStatus.FORBIDDEN,
                    "Acceso denegado: se requiere rol ADMIN");
        }

        ServerWebExchange exchangeModificado = exchange
                .mutate()
                .request(exchange.getRequest().mutate()
                        .header("X-Username",
                                jwtUtil.extraerUsername(token))
                        .header("X-Rol", rol)
                        .build())
                .build();

        return chain.filter(exchangeModificado);
    }

    @Override
    public int getOrder() {
        return -1;
    }

    private boolean esRutaPublica(String path) {
        return RUTAS_PUBLICAS.stream()
                .anyMatch(path::startsWith);
    }

    private boolean esSoloAdmin(String path) {
        return SOLO_ADMIN.stream()
                .anyMatch(path::startsWith);
    }

    private Mono<Void> rechazar(ServerWebExchange exchange,
                                HttpStatus status, String mensaje) {
        exchange.getResponse().setStatusCode(status);
        exchange.getResponse().getHeaders()
                .add("Content-Type", "application/json");
        var buffer = exchange.getResponse()
                .bufferFactory()
                .wrap(("{\"error\": \""
                        + mensaje + "\"}").getBytes());
        return exchange.getResponse()
                .writeWith(Mono.just(buffer));
    }
}