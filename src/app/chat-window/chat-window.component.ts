
// import {  NgFor, NgIf } from '@angular/common';
// import { Component } from '@angular/core';
// import { FormsModule} from '@angular/forms';


// @Component({
//   selector: 'app-chat-window',
//   standalone: true,
//   imports: [FormsModule,NgIf,NgFor],
//   templateUrl: './chat-window.component.html',
//   styleUrl: './chat-window.component.css'
// })
// export class ChatWindowComponent {
//   isChatOpen = true;
//   userMessage = '';
//   messages = [
//     { sender: 'bot', text: 'Hello! How can I help you today?' }
//   ];

//   toggleChat() {
//     this.isChatOpen = !this.isChatOpen;
//   }

//   sendMessage() {
//     if (this.userMessage.trim()) {
//       // Add user's message to the chat
//       this.messages.push({ sender: 'user', text: this.userMessage });

//       // Simulate a bot response
//       setTimeout(() => {
//         this.messages.push({ sender: 'bot', text: 'This is a bot response.' });
//       }, 1000);

//       // Clear the input field
//       this.userMessage = '';
//     }
//   }
// }



// import { Component } from '@angular/core';
// import { FormsModule } from '@angular/forms';
// import { NgFor, NgIf } from '@angular/common';

// @Component({
//   selector: 'app-chat-window',
//   standalone: true,
//   imports: [FormsModule, NgIf, NgFor],
//   templateUrl: './chat-window.component.html',
//   styleUrls: ['./chat-window.component.css']
// })
// export class ChatWindowComponent {
//   isChatOpen = true;
//   userMessage = '';
//   messages = [
//     { sender: 'bot', text: 'Hello! How can I help you today?' }
//   ];

//   faqList = [
//     { question: 'What is the main objective of the game?', answer: 'The main objective is to survive and uncover the secrets of Hollowpoint.' },
//     { question: 'How many characters can I play as?', answer: 'You can play as one of nine unique characters.' },
//     { question: 'Are there multiple endings in the game?', answer: 'Yes, the game features multiple endings based on your choices.' },
//     { question: 'What platforms is the game available on?', answer: 'The game is available on PC, PlayStation, and Xbox.' },
//     { question: 'Is the game single-player or multiplayer?', answer: 'The game is currently single-player.' }
//   ];

//   toggleChat() {
//     this.isChatOpen = !this.isChatOpen;
//   }

//   sendMessage() {
//     if (this.userMessage.trim()) {
//       this.messages.push({ sender: 'user', text: this.userMessage });

//       setTimeout(() => {
//         this.messages.push({ sender: 'bot', text: 'This is a bot response.' });
//       }, 1000);

//       this.userMessage = '';
//     }
//   }

//   askQuestion(question: string) {
//     this.messages.push({ sender: 'user', text: question });

//     const faq = this.faqList.find(f => f.question === question);
//     if (faq) {
//       setTimeout(() => {
//         this.messages.push({ sender: 'bot', text: faq.answer });
//       }, 1000);
//     }
//   }
// }

import { Component } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { NgFor, NgIf } from '@angular/common';

@Component({
  selector: 'app-chat-window',
  standalone: true,
  imports: [FormsModule, NgIf, NgFor],
  templateUrl: './chat-window.component.html',
  styleUrls: ['./chat-window.component.css']
})
export class ChatWindowComponent {
  isChatOpen = true;
  userMessage = '';
  messages = [
    { sender: 'bot', text: 'Hello! How can I help you today?' }
  ];

  faqList = [
    { question: 'What is the main objective of the game?', answer: 'The main objective is to survive and uncover the secrets of Hollowpoint.' },
    { question: 'How many characters can I play as?', answer: 'You can play as one of nine unique characters.' },
    { question: 'Are there multiple endings in the game?', answer: 'Yes, the game features multiple endings based on your choices.' },
    { question: 'What platforms is the game available on?', answer: 'The game is available on PC, PlayStation, and Xbox.' },
    { question: 'Is the game single-player or multiplayer?', answer: 'The game is currently single-player.' }
  ];

  toggleChat() {
    this.isChatOpen = !this.isChatOpen;
  }

  sendMessage() {
    if (this.userMessage.trim()) {
      this.messages.push({ sender: 'user', text: this.userMessage });

      setTimeout(() => {
        this.messages.push({ sender: 'bot', text: 'This is a bot response.' });
      }, 1000);

      this.userMessage = '';
    }
  }

  askQuestion(faq: { question: string; answer: string }) {
    // Add the question and answer to the chat messages
    this.messages.push({ sender: 'user', text: faq.question });
    setTimeout(() => {
      this.messages.push({ sender: 'bot', text: faq.answer });
    }, 1000);
  
    // Clear the entire FAQ list
    this.faqList = [];
  }
  
}



