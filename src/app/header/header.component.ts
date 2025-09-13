import { Component, OnInit } from '@angular/core';
import { RouterModule} from '@angular/router';
import { CartService } from '../services/cart.service';
import { NgIf } from '@angular/common';
import { ThemeToggleComponent } from '../theme-toggle/theme-toggle.component';

import { TranslateModule, TranslatePipe, TranslateService } from '@ngx-translate/core';
 





@Component({
  selector: 'app-header',
  standalone: true,
  imports: [NgIf,  RouterModule,ThemeToggleComponent,TranslatePipe,TranslateModule],
  templateUrl: './header.component.html',
  styleUrl: './header.component.css'
})
export class HeaderComponent implements OnInit {
    cartItemCount: number = 0
    selectedLanguage:string = 'en'
    constructor(private cartService: CartService,private translateService: TranslateService) {
      
        this.translateService.setDefaultLang(this.selectedLanguage)
       }

     

    ngOnInit(){
      this.cartService.cartCount$.subscribe(count => {
        this.cartItemCount = count
      })
      // this.loadGoogleTranslateScript()
    }

    menuOpen = false


    toggleMenu() {
      this.menuOpen = !this.menuOpen
    }

    closeMenu() {
      this.menuOpen = false
    }
   
   
    swichLanguage(lang:string){
      this.translateService.use(lang)
      this.selectedLanguage = lang;
    }
 
 
 
    /*---------------------------------- გუგლის თარგმანი----------------------*/

// "translate.google.com/translate_a/element.js?cb=googleTranslateElementInit"


  //    // Dynamically load the Google Translate script
  // private loadGoogleTranslateScript(): void {
  //   const scriptId = 'google-translate-script';
  //   if (!document.getElementById(scriptId)) {
  //     const script = document.createElement('script');
  //     script.id = scriptId;
  //     script.src =
  //       'https://translate.google.com/translate_a/element.js?cb=googleTranslateElementInit';
  //     script.async = true;
  //     script.defer = true;
  //     document.body.appendChild(script);

  //     // Define the callback function globally
  //     (window as any).googleTranslateElementInit = () => {
  //       this.initializeGoogleTranslate();
  //     };
  //   }
  // }

  // // Initialize the Google Translate widget
  // private initializeGoogleTranslate(): void {
  //   const googleTranslateElement = document.getElementById(
  //     'google_translate_element'
  //   );
  //   if (googleTranslateElement) {
  //     new (window as any).google.translate.TranslateElement(
  //       { pageLanguage: 'en', includedLanguages: 'en,ka' }, // Define the available languages
  //       'google_translate_element'
  //     );
  //   }
  // }
  // translateByGoogle(): void {
  //   const googleTranslateElement = document.getElementById('google_translate_element');
  //   if (googleTranslateElement) {
  //     new (window as any).google.translate.TranslateElement(
  //       { pageLanguage: 'en', includedLanguages: 'en,ka' }, // Define available languages
  //       'google_translate_element'
  //     );
  //   }
  // }
  
  }

