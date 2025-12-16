package com.sprintforge.apigateway.infrastructure.config.security;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.config.web.server.ServerHttpSecurity;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtProperties jwtProperties;

    @Bean
    public ReactiveJwtDecoder jwtDecoder() {
        SecretKey key = new SecretKeySpec(
                jwtProperties.getSecret().getBytes(StandardCharsets.UTF_8),
                "HmacSHA256"
        );

        NimbusReactiveJwtDecoder decoder =
                NimbusReactiveJwtDecoder.withSecretKey(key).build();

        OAuth2TokenValidator<Jwt> withIssuer =
                JwtValidators.createDefaultWithIssuer(jwtProperties.getIssuer());

        decoder.setJwtValidator(withIssuer);
        return decoder;
    }

    @Bean
    SecurityWebFilterChain security(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(ex -> ex
                                .pathMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                                .pathMatchers(HttpMethod.POST,
                                        "/api/v1/auth/login",
                                        "/api/v1/auth/set-initial-password",
                                        "/api/v1/auth/reset-password"
                                ).permitAll()
                                .anyExchange().permitAll()
                        //.anyExchange().authenticated()
                )
                .oauth2ResourceServer(oauth -> oauth.jwt(withDefaults()))
                .build();
    }
}
