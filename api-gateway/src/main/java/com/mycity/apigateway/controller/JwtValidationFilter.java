package com.mycity.apigateway.controller;


import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

@Component
public class JwtValidationFilter extends AbstractGatewayFilterFactory<JwtValidationFilter.Config> {

    private final Algorithm algorithm;
    private final WebClient.Builder webClientBuilder;
    private final String cookieName;

    
    
    
    public JwtValidationFilter(Config jwtConfig, WebClient.Builder webClientBuilder) {
        this.algorithm = Algorithm.HMAC256(jwtConfig.getSecret()); // Use HMAC256 Algorithm
        this.webClientBuilder = webClientBuilder;
        this.cookieName = jwtConfig.getCookieName();
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();

            // Define routes that don't require authentication
            if (request.getURI().getPath().startsWith("/auth")) {
                return chain.filter(exchange);
            }

            List<HttpCookie> cookies = request.getCookies().get(cookieName);

            if (CollectionUtils.isEmpty(cookies)) {
                return onError(exchange, "Missing " + cookieName + " cookie", HttpStatus.UNAUTHORIZED);
            }

            String token = cookies.get(0).getValue();

            try {
                DecodedJWT decodedJWT = JWT.require(algorithm)
                                           .build()
                                           .verify(token); // Verify JWT Token

                String role = decodedJWT.getClaim("role").asString();
                String email = decodedJWT.getSubject(); // Extract Subject
                System.out.println("This is email" +email);
                // Add user ID to headers for downstream services
                ServerHttpRequest modifiedRequest = exchange.getRequest().mutate()
                        .header("x-user-id", email)
                        .build();

                chain.filter(exchange.mutate().request(modifiedRequest).build());


                // Forward the request based on the role
                return forwardRequest(exchange, role);

            } catch (Exception e) {
                return onError(exchange, "Invalid or expired token", HttpStatus.UNAUTHORIZED);
            }
        };
    }

    private Mono<Void> forwardRequest(ServerWebExchange exchange, String role) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();
        String targetServiceUrl = null;

        if ("admin".equals(role)) {
            targetServiceUrl = "lb://ADMIN-SERVICE"; // Assign a single service URL for admin
        } else if ("user".equals(role)) {
            targetServiceUrl = "lb://USER-SERVICE"; // Assign a single service URL for users
        } else if ("merchant".equals(role)) {
            targetServiceUrl = "lb://MERCHANT-SERVICE"; // Assign a single service URL for merchants
        } 
        
        if (targetServiceUrl == null) {
            return onError(exchange, "No target service found for role: " + role + " and path: " + path, HttpStatus.NOT_FOUND);
        }

        WebClient webClient = webClientBuilder.build();

        return webClient.method(request.getMethod())
                .uri(targetServiceUrl + path)
                .headers(httpHeaders -> httpHeaders.addAll(request.getHeaders()))
                .body(request.getBody(), String.class)
                .exchangeToMono(clientResponse -> {
                    ServerHttpResponse response = exchange.getResponse();
                    response.setStatusCode(clientResponse.statusCode());
                    response.getHeaders().addAll(clientResponse.headers().asHttpHeaders());

                    return clientResponse.bodyToMono(String.class)
                            .flatMap(responseBody -> response.writeWith(Mono.just(response.bufferFactory().wrap(responseBody.getBytes()))));
                })
                .then();
    }

    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        System.err.println(err);
        return response.setComplete();
    }

    @Component
    public static class Config {
        @Value("${jwt.secret.user}")
        private String secret;

        @Value("${jwt.cookie-name:authToken}")
        private String cookieName;

        public String getSecret() {
            return secret;
        }

        public String getCookieName() {
            return cookieName;
        }

        public void setSecret(String secret) {
            this.secret = secret;
        }

        public void setCookieName(String cookieName) {
            this.cookieName = cookieName;
        }
    }
    
    //

//    @Configuration
//    public static class WebClientConfig {
//        @Bean
//        public WebClient.Builder webClientBuilder() {
//            return WebClient.builder();
//        }
//    }
}