package com.example.api;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

@Component
public class RequestRejectedEventHandler {
	private final Logger logger = LoggerFactory.getLogger(RequestRejectedEventHandler.class);

	@EventListener
	public void onRequestRejectedEvent(RequestRejectedEvent event) {
		this.logger.warn(String.format("Received %s event:", event.getClass().getSimpleName()),
			event.getException());
	}
}
