package com.example.api;

import io.micrometer.observation.ObservationRegistry;
import org.springframework.aop.Advisor;
import org.springframework.aop.Pointcut;
import org.springframework.aop.support.annotation.AnnotationMatchingPointcut;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.ObservationAuthorizationManager;
import org.springframework.security.authorization.method.AuthorizationManagerAfterMethodInterceptor;
import org.springframework.security.authorization.method.MethodInvocationResult;
import org.springframework.security.authorization.method.PostAuthorizeAuthorizationManager;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.SupplierJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.util.function.SingletonSupplier;

import static org.springframework.security.authorization.AuthorityAuthorizationManager.hasAuthority;
import static org.springframework.security.authorization.AuthorizationManagers.allOf;
import static org.springframework.security.authorization.AuthorizationManagers.anyOf;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = false)
public class SecurityConfiguration {

	@Bean
	public WebSecurityCustomizer webSecurityCustomizer(ApplicationEventPublisher eventPublisher) {
		return (web) -> web.requestRejectedHandler((request, response, requestRejectedException) -> {
			// Publish a custom event for RequestRejectedException
			RequestRejectedEvent event = new RequestRejectedEvent(requestRejectedException);
			eventPublisher.publishEvent(event);
			// Simply throw exception after publishing event
			throw requestRejectedException;
		});
	}

	static <T> AuthorizationManager<T> isJosh() {
		return (authentication, object) -> new AuthorizationDecision("josh".equals(authentication.get().getName()));
	}

	static AuthorizationManager<MethodInvocationResult> postAuthorize(ObjectProvider<ObservationRegistry> registry) {
		AuthorizationManager<MethodInvocationResult> authz = anyOf(isJosh(), new PostAuthorizeAuthorizationManager());
		return new SupplierAuthorizationManager<>(() -> new ObservationAuthorizationManager<>(registry.getObject(), authz));
	}

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	static Advisor postAuthorizeMethodInterceptor(ObjectProvider<ObservationRegistry> registry) {
		Pointcut pattern = new AnnotationMatchingPointcut(null, PostAuthorize.class);
		return new AuthorizationManagerAfterMethodInterceptor(pattern, postAuthorize(registry));
	}

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		// @formatter:off
		http
			.authorizeHttpRequests((authz) -> authz
				.requestMatchers("/flights/all").access(allOf(hasAuthority("flights:read"), isJosh()))
				.requestMatchers("/flights/*/take-off").access(allOf(hasAuthority("flights:write"), isJosh()))
				.requestMatchers("/flights").hasAuthority("flights:read")
				.anyRequest().hasAuthority("flights:write")
			)
			.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
		// @formatter:on

		return http.build();
	}

	@Bean
	JwtDecoder jwtDecoder(RestTemplateBuilder rest) {
		return new SupplierJwtDecoder(() -> NimbusJwtDecoder.withJwkSetUri("http://localhost:9000/oauth2/jwks")
				.restOperations(rest.build()).build());
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
