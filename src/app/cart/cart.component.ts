import { NgFor, NgIf } from '@angular/common';
import { Component, OnInit } from '@angular/core';
import { Pack } from '../services/pack';
import { CartService } from '../services/cart.service';
import Swal from 'sweetalert2';
import { RouterLink } from '@angular/router';
import { TranslatePipe } from '@ngx-translate/core';

@Component({
  selector: 'app-cart',
  standalone: true,
  imports: [TranslatePipe,NgFor, NgIf,RouterLink],
  templateUrl: './cart.component.html',
  styleUrl: './cart.component.css'
})
export class CartComponent implements OnInit{
        cartItems: Pack[] = []
        totalPrice: number = 0
        constructor(private cartService: CartService) {}

        ngOnInit() {
           this.cartItems = this.cartService.getCartItems()    
           this.cartService.totalPrice$.subscribe(price => {
            this.totalPrice = price; // Update the total price whenever it changes
          });      
        }

     removeFromCart(index: number) {
      this.cartService.removeCartItem(index)
      this.cartItems = this.cartService.getCartItems()
      Swal.fire({
        title: "Pack removed!",
        icon: "error",
        background: "rgb(29,24,25)",
          color: "beige",
          confirmButtonColor: "black",
          iconColor: "beige"
      });
     

     }  
     
   
}
