import { Component, Input } from '@angular/core';
import { Characters } from '../services/characters';
import { NgFor } from '@angular/common';


@Component({
  selector: 'app-characters-card',
  standalone: true,
  imports: [NgFor],
  templateUrl: './characters-card.component.html',
  styleUrl: './characters-card.component.css'
})
export class CharactersCardComponent {

@Input() characters!:Characters



}
