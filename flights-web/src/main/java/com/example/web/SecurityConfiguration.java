package com.example.web;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.security.web.server.csrf.ServerCsrfTokenRequestHandler;
import org.springframework.security.web.server.csrf.XorServerCsrfTokenRequestAttributeHandler;

@Configuration
public class SecurityConfiguration {

	@Bean
	SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
		// @formatter:off
		http
			.authorizeExchange((authorize) -> authorize
				.anyExchange().authenticated()
			)
			.oauth2Login(Customizer.withDefaults())
			.csrf((csrf) -> csrf
				.csrfTokenRequestHandler(new XorServerCsrfTokenRequestAttributeHandler()::handle)
				.csrfTokenRepository(CookieServerCsrfTokenRepository.withHttpOnlyFalse())
			);
		// @formatter:on
		return http.build();
	}

}
