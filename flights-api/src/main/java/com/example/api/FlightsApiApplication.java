package com.example.api;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.EnableTransactionManagement;

@SpringBootApplication
@EnableTransactionManagement(order = -1)
public class FlightsApiApplication {

	public static void main(String[] args) {
		SpringApplication.run(FlightsApiApplication.class, args);
	}

	@Component
	static class FlightDataInitializer implements CommandLineRunner {

		private final FlightRepository flightRepository;

		FlightDataInitializer(FlightRepository flightRepository) {
			this.flightRepository = flightRepository;
		}

		@Override
		public void run(String... args) {
			this.flightRepository.save(new Flight("101", "josh", Flight.Status.TAXI));
			this.flightRepository.save(new Flight("102", "marcus", Flight.Status.BOARD));
			this.flightRepository.save(new Flight("103", "steve", Flight.Status.BOARD));
		}

	}
}
