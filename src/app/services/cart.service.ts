import { Injectable } from '@angular/core';
import { Pack } from './pack';
import { BehaviorSubject } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class CartService {

  private cart: Pack[] = []
  private cartCount = new BehaviorSubject<number>(0)
  private totalPrice = new BehaviorSubject<number>(0);

  cartCount$ = this.cartCount.asObservable()
  totalPrice$ = this.totalPrice.asObservable();

  addPackToCart(pack: Pack): void {
    if (!this.cart.some((item) => item.name === pack.name)) {
      this.cart.push(pack);
      this.cartCount.next(this.cart.length);
      this.updateTotalPrice()
    }
  }
  getCartItems() {
    return this.cart;
  }

  removeCartItem(index: number) {
    this.cart.splice(index,1)
    this.cartCount.next(this.cart.length)
    this.updateTotalPrice()
  }
  isPackInCart(pack: Pack): boolean {
    return this.cart.some((cartPack) => cartPack.name === pack.name);
  }

  private updateTotalPrice() {
    const total = this.cart.reduce((total, item) => total + item.price, 0);
    this.totalPrice.next(total); // Notify subscribers with the new total price
  }

  constructor() { }
}
