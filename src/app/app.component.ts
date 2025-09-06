import { Component } from '@angular/core';
import { RouterOutlet } from '@angular/router';
import { HeaderComponent } from './header/header.component';
import { FooterComponent } from './footer/footer.component';
import { ChatIconComponent } from './chat-icon/chat-icon.component';



@Component({
  selector: 'app-root',
  standalone: true,
  imports: [RouterOutlet,HeaderComponent,FooterComponent,ChatIconComponent,],
  templateUrl: './app.component.html',
   styleUrl: './app.component.css'
})
export class AppComponent {
  title = 'game';
}







