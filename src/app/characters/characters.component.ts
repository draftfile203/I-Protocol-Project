import { Component,inject } from '@angular/core';
import { GetDataService } from '../services/get-data.service';
import { Characters } from '../services/characters';
import { CommonModule, NgFor, NgIf } from '@angular/common';
import { CharactersCardComponent } from '../characters-card/characters-card.component';
import { HeaderComponent } from '../header/header.component';


@Component({
  selector: 'app-characters',
  standalone: true,
  imports: [NgFor,CharactersCardComponent, HeaderComponent, NgIf,CommonModule],
  templateUrl: './characters.component.html',
  styleUrl: './characters.component.css'
})
export class CharactersComponent {

  title:string = 'myCharacters'

  dataService: GetDataService = inject(GetDataService)

  charactersList: Characters[] = []

  isLoading: boolean = true

  displayedCharactersCount = 6

  constructor() {
    this.loadCharacters()
  }

  async loadCharacters(refresh:boolean = false) {
    try{
    this.isLoading = true
    console.log("loading started...")

    await new Promise(resolve => setTimeout(resolve,1000))

    this.charactersList = await this.dataService.getData(refresh)
    console.log(this.charactersList)
  } catch (error) {
    console.error('Error fetching characters', error)
  } finally {
    this.isLoading = false
  }

}

refreshCharacters() {
  this.loadCharacters(true);
}

showMore() {
  this.displayedCharactersCount = Math.min(this.displayedCharactersCount + 3, this.charactersList.length)
}
}
