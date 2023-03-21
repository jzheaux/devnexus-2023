package com.example.api;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

	@Autowired
	private ApplicationEventPublisher eventPublisher;

	@Override
	public void configure(WebSecurity web) {
		web.requestRejectedHandler((request, response, requestRejectedException) -> {
			// Publish a custom event for RequestRejectedException
			RequestRejectedEvent event = new RequestRejectedEvent(requestRejectedException);
			this.eventPublisher.publishEvent(event);
			// Simply throw exception after publishing event
			throw requestRejectedException;
		});
	}

	@Override
	public void configure(HttpSecurity http) throws Exception {
		// @formatter:off
		http
			.authorizeRequests((authz) -> authz
				.mvcMatchers("/flights/all").access("hasAuthority('flights:read') and authentication.name == 'josh'")
				.mvcMatchers("/flights/*/take-off").access("hasAuthority('flights:write') and authentication.name == 'josh'")
				.mvcMatchers("/flights").hasAuthority("flights:read")
				.anyRequest().hasAuthority("flights:write")
			)
			.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
		// @formatter:on
	}

	@Bean
	public JwtAuthenticationConverter jwtAuthenticationConverter() {
		JwtGrantedAuthoritiesConverter authoritiesConverter = new JwtGrantedAuthoritiesConverter();
		authoritiesConverter.setAuthorityPrefix("");
		JwtAuthenticationConverter authenticationConverter = new JwtAuthenticationConverter();
		authenticationConverter.setJwtGrantedAuthoritiesConverter(authoritiesConverter);
		return authenticationConverter;
	}
}
