import { Component } from '@angular/core';
import { Pack } from '../services/pack';
import { CartService } from '../services/cart.service';
import { NgFor } from '@angular/common';
import Swal from 'sweetalert2';


@Component({
  selector: 'app-packs',
  standalone: true,
  imports: [NgFor],
  templateUrl: './packs.component.html',
  styleUrl: './packs.component.css'
})
export class PacksComponent {
     packs: Pack[] = [
      
        { name: 'Free Plan', price: 0, duration: '', features: ['Basic features', '2 Characters', 'Community Support'] },
        { name: 'Monthly Plan', price: 15, duration: '/month', features: ['All Basic Features', '5 Characters', 'Email Support'] },
        { name: 'Yearly Plan', price: 120, duration: '/year', features: ['All Premium Features', 'All Characters', 'Priority Support'] }
      ];
      constructor(private cartService: CartService) {}

      addToCart(pack : Pack) {
      
        this.cartService.addPackToCart(pack)
        Swal.fire({
          title: "Pack added!",
          icon: "success",
          background: "rgb(29,24,25)",
          color: "beige",
          confirmButtonColor: "black",
          iconColor: "beige"
        });
      }
      
      isInCart(pack: Pack): boolean {
       
        return this.cartService.getCartItems().some((item) => item.name === pack.name);
      
      }
     }   


