import { Component , OnInit} from '@angular/core';
import { FormGroup, FormBuilder, ReactiveFormsModule } from '@angular/forms';
import { AdminService } from '../adminServices/admin.service';
import { Characters } from '../../services/characters';
import { NgFor } from '@angular/common';
import { response } from 'express';
import { GetDataService } from '../../services/get-data.service';
import Swal from 'sweetalert2';



@Component({
  selector: 'app-admindashboard',
  standalone: true,
  imports: [NgFor, ReactiveFormsModule],
  templateUrl: './admindashboard.component.html',
  styleUrl: './admindashboard.component.css'
})
export class AdmindashboardComponent  implements OnInit{

  characterForm: FormGroup
  characters: Characters[] = []
  selectedCharacterId: string | null = null


  constructor(private fb: FormBuilder, private adminService: AdminService, private getDataService: GetDataService) {

    this.characterForm = this.fb.group({
      img: [''],
      name: [''],
      role:[]
    })
  }

  ngOnInit(): void {
    this.fetchCharacters()
  }

  fetchCharacters(): void {
    const cachedData = localStorage.getItem('charactersData') 

    if(cachedData) {
      this.characters = JSON.parse(cachedData)
    } else {
      this.getDataService.getData().then((characters) => {
        this.characters = characters
      })
    }
  }


  onAdd(): void {
    const newCharacter: Characters = this.characterForm.value
    this.adminService.addCharacter(newCharacter).subscribe(response => {
      console.log('Character added:', response)
      this.characterForm.reset()
      this.fetchCharacters(); 
      Swal.fire({
        title: "SUCCESS",
        text: "Character added",
        icon: "success",
        background: "#1d1819",
        color: "#f5f5dc",
        iconColor: "#808080",
        confirmButtonColor: "#808080"
      });
    })
  }

  onUpdate(): void {
    if (this.selectedCharacterId) {
      const updatedCharacter: Characters = this.characterForm.value
      this.adminService.updateCharacter(this.selectedCharacterId,updatedCharacter).subscribe(response => {
        console.log('Character updated:', response)
        this.characterForm.reset()
        this.selectedCharacterId = null
        this.fetchCharacters(); 
        Swal.fire({
          title: "SUCCESS",
          text: "Character updated",
          icon: "success",
          background: "#1d1819",
          color: "#f5f5dc",
          iconColor: "#808080",
          confirmButtonColor: "#808080"
        });
      })
    }
  }

  onDelete(): void {
    if(this.selectedCharacterId) {
      this.adminService.deleteCharacter(this.selectedCharacterId).subscribe(() => {
        console.log('Character deleted')
        this.characterForm.reset()
        this.selectedCharacterId = null
        this.fetchCharacters(); 
        Swal.fire({
          title: "complete",
          text: "Character deleted",
          icon: "error",
          background: "#1d1819",
          color: "#f5f5dc",
          iconColor: "#808080",
          confirmButtonColor: "#808080"
        });
      })
    }
  }

  selectCharacter(character: Characters, id:string): void {
    this.selectedCharacterId = id
    this.characterForm.patchValue(character)
  }
} 