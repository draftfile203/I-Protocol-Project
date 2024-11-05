import { NgIf } from '@angular/common';
import { Component } from '@angular/core';
import { FormBuilder, FormGroup, Validators, ReactiveFormsModule } from '@angular/forms';
import Swal from 'sweetalert2';


@Component({
  selector: 'app-register',
  standalone: true,
  imports: [ReactiveFormsModule,NgIf],
  templateUrl: './register.component.html',
  styleUrl: './register.component.css'
})
export class RegisterComponent {

  registerForm: FormGroup;

  constructor(private fb: FormBuilder) {
    this.registerForm = this.fb.group({
      email: ['',[Validators.required,Validators.email]],
      password: ['',[Validators.required,Validators.minLength(6)]]
    });
  }

  onSubmit() {
    if(this.registerForm.valid) {
      const formData = this.registerForm.value;

      localStorage.setItem('RegisteredUser', JSON.stringify(formData))

      console.log('user registered:', formData)
      Swal.fire({
        title: "SUCCESS",
        text: "You are registered",
        icon: "success",
        background: "#1d1819",
        color: "#f5f5dc",
        iconColor: "#808080",
        confirmButtonColor: "#808080"
      });

      this.registerForm.reset()
    } else {
      Swal.fire({
        icon: "error",
        title: "Oops...",
        text: "Something went wrong!",
      });
    }
  }

}
