import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';


export const authGuard: CanActivateFn = (route, state) => {
  const router = inject(Router)
  if(typeof window !== 'undefined') {
    const isLoggedIn = !!localStorage.getItem('isLoggedIn')
    
    if (isLoggedIn) {
      return true;
    }  
  }
      router.navigate(['/admin'])
      return false;
  
  
};
