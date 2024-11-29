import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable,map } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class AuthService {

  private apiUrl = 'https://670581af031fd46a83103c90.mockapi.io/users'

  constructor(private http: HttpClient) { }

  register(userData: { email: string, password : string}): Observable<any> {
    return this.http.post (`${this.apiUrl}`,userData)
  }

  login(userData: { email: string, password: string }): Observable<any> {
    return this.http.get<any[]>(`${this.apiUrl}`).pipe(
      map(users => {
       
        const user = users.find(
          u => u.email === userData.email && u.password === userData.password
        );
  
       
        return user ? { success: true, user } : { success: false, message: "Invalid credentials" };
      })
    );
  }


}
