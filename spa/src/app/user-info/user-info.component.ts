import { Component } from '@angular/core';
import { Observable } from 'rxjs';

import { UserService } from '../services/user.service';

@Component({
  selector: 'app-user-info',
  templateUrl: './user-info.component.html',
  styleUrls: ['./user-info.component.scss']
})
export class UserInfoComponent {

  user$: Observable<any>;

  constructor(
    private userService: UserService,
  ) {
    this.user$ = this.userService.getUserInfo();
  }

}
