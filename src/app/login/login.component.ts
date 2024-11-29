import { Component } from '@angular/core';
import { FormBuilder, FormGroup, Validators, ReactiveFormsModule, FormsModule } from '@angular/forms';
import { AuthService } from '../services/auth.service';
import Swal from 'sweetalert2';
import { RouterModule } from '@angular/router';


@Component({
  selector: 'app-login',
  standalone: true,
  imports: [ReactiveFormsModule, RouterModule, FormsModule],
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.css']
})
export class LoginComponent {
  loginForm: FormGroup;

  constructor(private fb: FormBuilder, private authService: AuthService) {
    this.loginForm = this.fb.group({
      email: ['', [Validators.required, Validators.email]],
      password: ['', [Validators.required]]
    });
  }

  onSubmit() {
    if (this.loginForm.valid) {
      const formData = this.loginForm.value;

      this.authService.login(formData).subscribe(response => {

      if(response.success){
          Swal.fire({
            title: 'Welcome!',
            text: 'You are logged in',
            icon: 'success',
          });
          this.loginForm.reset()
        }
         else {
          Swal.fire({
            icon: 'error',
            title: 'Login Failed',
            text: 'Invalid email or password!',
          });
        }
    
      })
  }

}
}