package com.example.api;

import java.util.function.Supplier;

import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.util.function.SingletonSupplier;

public class SupplierAuthorizationManager<T> implements AuthorizationManager<T> {
	private final Supplier<AuthorizationManager<T>> manager;

	public SupplierAuthorizationManager(Supplier<AuthorizationManager<T>> manager) {
		this.manager = SingletonSupplier.of(manager);
	}

	@Override
	public AuthorizationDecision check(Supplier<Authentication> authentication, T object) {
		return this.manager.get().check(authentication, object);
	}
}
