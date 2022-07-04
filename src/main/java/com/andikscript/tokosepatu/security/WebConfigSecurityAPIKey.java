package com.andikscript.tokosepatu.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.SecurityFilterChain;

// class yang digunakan untuk authorize api key yang diambil dari header
@Configuration
@EnableWebSecurity
@Order(1)
public class WebConfigSecurityAPIKey {

    @Value("${TokoSepatu.http.auth-token-header-name}")
    private String principalRequestHeader;

    @Value("${TokoSepatu.http.auth-token}")
    private String principalRequestValue;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        APIKeyAuthFilter filter = new APIKeyAuthFilter(principalRequestHeader);
        filter.setAuthenticationManager(new AuthenticationManager() {
            @Override
            public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                String principal = (String) authentication.getPrincipal();

                if (!principalRequestValue.equals(principal)) {
                    throw new BadCredentialsException("The API Key not found or not the expected value");
                }
                authentication.setAuthenticated(true);
                return authentication;
            }
        });

        httpSecurity
                .antMatcher("/api/**")
                .csrf()
                .disable()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilter(filter)
                .authorizeRequests()
                .anyRequest()
                .authenticated();
        return httpSecurity.build();
    }
}
