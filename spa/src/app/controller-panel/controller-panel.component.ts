import { Component } from '@angular/core';
import { Observable } from 'rxjs';
import { Flight, FlightsService } from '../services/flights.service';

@Component({
  selector: 'app-controller-panel',
  templateUrl: './controller-panel.component.html',
  styleUrls: ['./controller-panel.component.scss']
})
export class ControllerPanelComponent {

  flights$: Observable<Flight[]>;

  constructor(
    private flightsService: FlightsService,
  ) {
    this.flights$ = this.flightsService.getAllFlights();
  }

  updateFlights(): void {
    this.flights$ = this.flightsService.getAllFlights();
  }

  updateStatus(flight: Flight, newStatus: string) {
    this.flightsService.updateFlight(flight.flightNumber, newStatus)
        .subscribe(() => flight.status = newStatus);
  }
}
