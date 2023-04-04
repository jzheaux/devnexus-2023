package com.example.sso;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.context.DelegatingSecurityContextRepository;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.csrf.XorCsrfTokenRequestAttributeHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import static org.springframework.beans.factory.config.BeanDefinition.ROLE_INFRASTRUCTURE;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

	@Bean
	@Order(1)
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
		http.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(Customizer.withDefaults());

		HttpSessionRequestCache requestCache = new HttpSessionRequestCache();
		// **** Enable optimized querying of the RequestCache ****
		// https://docs.spring.io/spring-security/reference/5.8/migration/servlet/session-management.html#requestcache-query-optimization
		requestCache.setMatchingRequestParameterName("continue");

		// @formatter:off
		http
			.securityContext((securityContext) -> securityContext
				// **** Enable writing the SecurityContext to HttpSession explicitly ****
				// https://docs.spring.io/spring-security/reference/5.8/migration/servlet/session-management.html#_require_explicit_saving_of_securitycontextrepository
				.requireExplicitSave(true)
				// **** Enable propagating SecurityContext to other dispatch types (e.g. forward) ****
				// https://docs.spring.io/spring-security/reference/5.8/migration/servlet/session-management.html#_change_httpsessionsecuritycontextrepository_to_delegatingsecuritycontextrepository
				.securityContextRepository(new DelegatingSecurityContextRepository(
					new RequestAttributeSecurityContextRepository(),
					new HttpSessionSecurityContextRepository()
				))
			)
			.requestCache((cache) -> cache
				// **** Use customized RequestCache ****
				.requestCache(requestCache)
			)
			.sessionManagement((sessions) -> sessions
				// **** Enable invocation of the SessionAuthenticationStrategy explicitly ****
				// https://docs.spring.io/spring-security/reference/5.8/migration/servlet/session-management.html#_require_explicit_invocation_of_sessionauthenticationstrategy
				.requireExplicitAuthenticationStrategy(true)
			)
			.oauth2ResourceServer((oauth2) -> oauth2
				.jwt(Customizer.withDefaults())
			)
			.exceptionHandling((exceptions) -> exceptions
				.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
			);
		// @formatter:on

		return http.build();
	}

	@Bean
	@Order(2)
	public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
		HttpSessionRequestCache requestCache = new HttpSessionRequestCache();
		// **** Enable optimized querying of the RequestCache ****
		// https://docs.spring.io/spring-security/reference/5.8/migration/servlet/session-management.html#requestcache-query-optimization
		requestCache.setMatchingRequestParameterName("continue");

		// **** Enable BREACH protection of the CsrfToken ****
		// https://docs.spring.io/spring-security/reference/5.8/migration/servlet/exploits.html#_protect_against_csrf_breach
		XorCsrfTokenRequestAttributeHandler requestHandler = new XorCsrfTokenRequestAttributeHandler();
		// **** Enable deferred loading of the CsrfToken ****
		// https://docs.spring.io/spring-security/reference/5.8/migration/servlet/exploits.html#_defer_loading_csrftoken
		requestHandler.setCsrfRequestAttributeName("_csrf");

		// @formatter:off
		http
			.authorizeHttpRequests((authorize) -> authorize
				// **** Enable filtering on all dispatcher types ****
				// https://docs.spring.io/spring-security/reference/5.8/migration/servlet/authorization.html#switch-filter-all-dispatcher-types
				.shouldFilterAllDispatcherTypes(true)
				.requestMatchers("/login", "/webjars/**", "/assets/**", "/favicon.ico").permitAll()
				.anyRequest().authenticated()
			)
			.securityContext((securityContext) -> securityContext
				// **** Enable writing the SecurityContext to HttpSession explicitly ****
				// https://docs.spring.io/spring-security/reference/5.8/migration/servlet/session-management.html#_require_explicit_saving_of_securitycontextrepository
				.requireExplicitSave(true)
				// **** Enable propagating SecurityContext to other dispatch types (e.g. forward) ****
				// https://docs.spring.io/spring-security/reference/5.8/migration/servlet/session-management.html#_change_httpsessionsecuritycontextrepository_to_delegatingsecuritycontextrepository
				.securityContextRepository(new DelegatingSecurityContextRepository(
					new RequestAttributeSecurityContextRepository(),
					new HttpSessionSecurityContextRepository()
				))
			)
			.requestCache((cache) -> cache
				// **** Use customized RequestCache ****
				.requestCache(requestCache)
			)
			.sessionManagement((sessions) -> sessions
				// **** Enable invocation of the SessionAuthenticationStrategy explicitly ****
				// https://docs.spring.io/spring-security/reference/5.8/migration/servlet/session-management.html#_require_explicit_invocation_of_sessionauthenticationstrategy
				.requireExplicitAuthenticationStrategy(true)
			)
			.csrf((csrf) -> csrf
				// **** Use customized CsrfTokenRequestHandler ****
				.csrfTokenRequestHandler(requestHandler)
			)
			.formLogin((formLogin) -> formLogin.loginPage("/login"))
			.saml2Login((saml2Login) -> saml2Login.loginPage("/login"))
			.logout(Customizer.withDefaults());
		// @formatter:on

		return http.build();
	}

	@Bean
	public RegisteredClientRepository registeredClientRepository() {
		// @formatter:off
		RegisteredClient webClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("air-traffic-control")
				.clientSecret("{noop}secret")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.redirectUri("http://127.0.0.1:8000/login/oauth2/code/air-traffic-control-client")
				.scope(OidcScopes.OPENID)
				.scope("flights:read")
				.scope("flights:write")
				.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
				.build();
		RegisteredClient apiClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("josh")
				.clientSecret("{noop}control")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.scope("flights:read")
				.scope("flights:write")
				.build();
		// @formatter:on

		return new InMemoryRegisteredClientRepository(webClient, apiClient);
	}

	@Bean
	public JWKSource<SecurityContext> jwkSource(KeyPair keyPair) {
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		// @formatter:off
		RSAKey rsaKey = new RSAKey.Builder(publicKey)
				.privateKey(privateKey)
				.keyID(UUID.randomUUID().toString())
				.build();
		JWKSet jwkSet = new JWKSet(rsaKey);
		return new ImmutableJWKSet<>(jwkSet);
	}

	@Bean
	public JwtDecoder jwtDecoder(KeyPair keyPair) {
		return NimbusJwtDecoder.withPublicKey((RSAPublicKey) keyPair.getPublic()).build();
	}

	@Bean
	public AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder().build();
	}

	@Bean
	public UserDetailsService userDetailsService() {
		UserDetails josh = User.withDefaultPasswordEncoder()
				.username("josh")
				.password("control")
				.roles("USER")
				.build();
		UserDetails marcus = User.withDefaultPasswordEncoder()
				.username("marcus")
				.password("password")
				.roles("USER")
				.build();
		UserDetails steve = User.withDefaultPasswordEncoder()
				.username("steve")
				.password("password")
				.roles("USER")
				.build();
		return new InMemoryUserDetailsManager(josh, marcus, steve);
	}

	@Bean
	@Role(ROLE_INFRASTRUCTURE)
	KeyPair generateRsaKey() {
		KeyPair keyPair;
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			keyPair = keyPairGenerator.generateKeyPair();
		}
		catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
		return keyPair;
	}

}
