import { CommonModule } from '@angular/common';
import { Component } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router, RouterModule } from '@angular/router';
import Swal from 'sweetalert2';

@Component({
  selector: 'app-adminlogin',
  standalone: true,
  imports: [FormsModule, CommonModule, RouterModule],
  templateUrl: './adminlogin.component.html',
  styleUrl: './adminlogin.component.css'
})
export class AdminloginComponent {
     
  username: string=''
  password:string=''


  private readonly adminUsername: string= 'admin';
  private readonly adminPassword: string = 'password';


  constructor(private router:Router){}

  onLogin(): void {
    if(this.username === this.adminUsername && this.password === this.adminPassword){
      localStorage.setItem('isLoggedIn', 'true')
      this.router.navigate(['/admin/dashboard'])  
      
    } else {
      Swal.fire({
        icon: "error",
        title: "Oops...",
        text: "Invalid credits!",
        background: "#1d1819",
        color: "#f5f5dc",
        iconColor: "red",
        confirmButtonColor: "#808080"
      })
      localStorage.removeItem('isLoggedIn')
    }
  }

}
