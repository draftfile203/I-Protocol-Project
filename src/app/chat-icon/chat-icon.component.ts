import { Component } from '@angular/core';
import { ChatWindowComponent } from '../chat-window/chat-window.component';
import { NgIf } from '@angular/common';


@Component({
  selector: 'app-chat-icon',
  standalone: true,
  imports: [ChatWindowComponent,NgIf],
  templateUrl: './chat-icon.component.html',
  styleUrl: './chat-icon.component.css'
})
export class ChatIconComponent {
  isChatOpen = false;

  toggleChat() {
    this.isChatOpen = !this.isChatOpen;
  }

}
