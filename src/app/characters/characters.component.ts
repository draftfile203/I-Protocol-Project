import { Component,inject, PLATFORM_ID } from '@angular/core';
import { GetDataService } from '../services/get-data.service';
import { Characters } from '../services/characters';
import { CommonModule, isPlatformBrowser, NgFor, NgIf } from '@angular/common';
import { CharactersCardComponent } from '../characters-card/characters-card.component';
import { HeaderComponent } from '../header/header.component';
import { FormsModule } from '@angular/forms';


@Component({
  selector: 'app-characters',
  standalone: true,
  imports: [NgFor,CharactersCardComponent, HeaderComponent, NgIf,CommonModule,FormsModule],
  templateUrl: './characters.component.html',
  styleUrl: './characters.component.css'
})
export class CharactersComponent {

  title:string = 'myCharacters'

  dataService: GetDataService = inject(GetDataService)

  platformId = inject(PLATFORM_ID)

  charactersList: Characters[] = []

  filteredCharacterList: Characters [] = []

  searchTerm: string = ''

  isLoading: boolean = true

  displayedCharactersCount = 6

  constructor(private dataservice: GetDataService) {
    if (isPlatformBrowser(this.platformId)){
    this.loadCharacters()
    }
  }

  async loadCharacters(refresh:boolean = false) {
    try{
    this.isLoading = true
    console.log("loading started...")

    await new Promise(resolve => setTimeout(resolve,1000))

    this.charactersList = await this.dataService.getData(refresh)
    this.filteredCharacterList = this.charactersList
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
  this.displayedCharactersCount = Math.min(this.displayedCharactersCount + 3, this.filteredCharacterList.length)
}

onSearchChange() {
  this.filteredCharacterList = this.charactersList.filter((character) =>
   character.name.toLowerCase().includes(this.searchTerm.toLowerCase()))
   
  this.displayedCharactersCount = Math.min(this.filteredCharacterList.length,6)
 
}
}
