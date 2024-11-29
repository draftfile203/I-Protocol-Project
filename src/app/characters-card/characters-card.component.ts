import { Component, Input } from '@angular/core';
import { Characters } from '../services/characters';
import { NgFor } from '@angular/common';
import { GetDataService } from '../services/get-data.service';


@Component({
  selector: 'app-characters-card',
  standalone: true,
  imports: [NgFor],
  templateUrl: './characters-card.component.html',
  styleUrl: './characters-card.component.css'
})
export class CharactersCardComponent {

@Input() characters!:Characters

characterList: Characters [] = []


constructor(private getDataService: GetDataService) {}

async ngOnInit(): Promise<void> {
  try {
    this.characterList = await this.getDataService.getData();
  } catch (error) {
    console.error('Error fetching characters:', error);
  }
}

}
