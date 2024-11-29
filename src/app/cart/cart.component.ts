import { NgFor, NgIf } from '@angular/common';
import { Component, OnInit } from '@angular/core';
import { Pack } from '../services/pack';
import { CartService } from '../services/cart.service';

import { RouterLink } from '@angular/router';

@Component({
  selector: 'app-cart',
  standalone: true,
  imports: [NgFor, NgIf,RouterLink],
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
     

     }  
     
   
}
