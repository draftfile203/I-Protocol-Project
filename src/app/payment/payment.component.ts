import { Component, OnInit } from '@angular/core';
import { CartService } from '../services/cart.service';
import Swal from 'sweetalert2';
import { NgClass } from '@angular/common';
import { FormsModule } from '@angular/forms';

@Component({
  selector: 'app-payment',
  standalone: true,
  imports: [NgClass,FormsModule],
  templateUrl: './payment.component.html',
  styleUrl: './payment.component.css'
})
export class PaymentComponent implements OnInit{
 totalPrice = 0

 personName = '';
 cardNumber = '';
 expiry = '';
 cvv = '';
  constructor ( private cartService: CartService) {}
  ngOnInit() {
    this.cartService.totalPrice$.subscribe(price => {
      this.totalPrice = price
    })
  }

  isFormValid(): boolean {
    // Simple validation logic
    const nameValid = this.personName.trim().length > 0;
    const cardNumberValid = /^\d{16}$/.test(this.cardNumber.replace(/\s+/g, '')); // Validate 16 digits
    const expiryValid = /^(0[1-9]|1[0-2])\/\d{4}$/.test(this.expiry); // Validate MM/YYYY format
    const cvvValid = /^\d{3}$/.test(this.cvv); // Validate 3-digit CVV

    return nameValid && cardNumberValid && expiryValid && cvvValid;
  }
  
  pay(): void {
    if (this.isFormValid()) {
      Swal.fire({
        title: 'Payment Successful',
        background: 'rgb(29,24,23)',
        color: 'beige',
        confirmButtonColor: 'rgb(112, 112, 93)'
      });
      
    } else {
      Swal.fire({
        title: 'Please fill out all fields correctly',
        background: 'rgb(29,24,23)',
        color: 'red',
        confirmButtonColor: 'rgb(112, 112, 93)',
        
      });
    }
  }
}