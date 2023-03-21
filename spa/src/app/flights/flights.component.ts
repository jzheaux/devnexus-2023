import { Component } from '@angular/core';
import { Observable } from 'rxjs';
import { Flight, FlightsService } from '../services/flights.service';

@Component({
  selector: 'app-flights',
  templateUrl: './flights.component.html',
  styleUrls: ['./flights.component.scss']
})
export class FlightsComponent {

  flights$: Observable<Flight[]>;

  constructor(
    private flightsService: FlightsService
  ) {
    this.flights$ = this.flightsService.getFlights();
  }

  updateStatus(flight: Flight, newStatus: string) {
    this.flightsService.updateFlight(flight.flightNumber, newStatus)
        .subscribe(() => flight.status = newStatus);
  }

  updateFlights(): void {
    this.flights$ = this.flightsService.getFlights();
  }

}
