import {  NgFor, NgIf } from '@angular/common';
import { Component } from '@angular/core';

@Component({
  selector: 'app-about',
  standalone: true,
  imports: [NgIf, NgFor],
  templateUrl: './about.component.html',
  styleUrl: './about.component.css'
})
export class AboutComponent {
  faqList = [
    { question: 'What is the main objective of the game?', answer: 'The main objective is to survive and uncover the secrets of Hollowpoint.', showAnswer: false },
    { question: 'How many characters can I play as?', answer: 'You can play as one of nine unique characters.', showAnswer: false },
    { question: 'Are there multiple endings in the game?', answer: 'Yes, the game features multiple endings based on your choices.', showAnswer: false },
    { question: 'What platforms is the game available on?', answer: 'The game is available on PC, PlayStation, and Xbox.', showAnswer: false },
    { question: 'Is the game single-player or multiplayer?', answer: 'The game is currently single-player.', showAnswer: false }
  ];

  toggleAnswer(index: number) {
    this.faqList[index].showAnswer = !this.faqList[index].showAnswer;
  }
}
