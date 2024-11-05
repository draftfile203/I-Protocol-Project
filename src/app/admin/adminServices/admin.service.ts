import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { Characters } from '../../services/characters';

@Injectable({
  providedIn: 'root'
})
export class AdminService {

  private apiUrl = 'https://670581af031fd46a83103c90.mockapi.io/characters'

  constructor(private http: HttpClient) { }

  addCharacter(character:Characters): Observable<any> {
     return this.http.post(`${this.apiUrl}`, character)
  }

  updateCharacter(id: string, character :Characters): Observable<any>{
     return this.http.put(`${this.apiUrl}/${id}`,character)
  }

  deleteCharacter(id:string): Observable<any> {
     return this.http.delete(`${this.apiUrl}/${id}`)
  }

}
