
import { Component } from '@angular/core';
import { ChatIconComponent } from '../chat-icon/chat-icon.component';

@Component({
  selector: 'app-home',
  standalone: true,
  imports: [ChatIconComponent],
  templateUrl: './home.component.html',
  styleUrl: './home.component.css'
})
export class HomeComponent {

}

