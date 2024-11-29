import { Component, OnInit } from '@angular/core';
import { RouterModule} from '@angular/router';
import { CartService } from '../services/cart.service';
import { NgIf } from '@angular/common';
 





@Component({
  selector: 'app-header',
  standalone: true,
  imports: [NgIf,  RouterModule],
  templateUrl: './header.component.html',
  styleUrl: './header.component.css'
})
export class HeaderComponent implements OnInit {
    cartItemCount: number = 0

    constructor(private cartService: CartService ) {
    }

  

    ngOnInit(){
      this.cartService.cartCount$.subscribe(count => {
        this.cartItemCount = count
      })
      
    }

    menuOpen = false
  

    toggleMenu() {
      this.menuOpen = !this.menuOpen
    }

    closeMenu() {
      this.menuOpen = false
    }

    
  }
