package com.example.api;

import org.springframework.context.ApplicationEvent;
import org.springframework.security.web.firewall.RequestRejectedException;

public class RequestRejectedEvent extends ApplicationEvent {
	public RequestRejectedEvent(RequestRejectedException exception) {
		super(exception);
	}

	public RequestRejectedException getException() {
		return (RequestRejectedException) this.getSource();
	}
}
