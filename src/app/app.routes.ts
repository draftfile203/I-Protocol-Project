import { Routes } from '@angular/router';
import { HomeComponent } from './home/home.component';
import { AboutComponent } from './about/about.component';
import { CharactersComponent } from './characters/characters.component';
import { DownloadComponent } from './download/download.component';
import { RegisterComponent } from './register/register.component';
import { LoginComponent } from './login/login.component';
import { PacksComponent } from './packs/packs.component';
import { CartComponent } from './cart/cart.component';
import { PaymentComponent } from './payment/payment.component';


export const routes: Routes = [
    {path: "", component:HomeComponent},
    {path: "about", component:AboutComponent},
    {path: "characters", component:CharactersComponent},
    {path: "download", component:DownloadComponent},
    {path: "register", component:RegisterComponent},
    {path: "login",component: LoginComponent},
    {path: "packs", component:PacksComponent},
    {path: "cart", component:CartComponent},
    {path: "payment", component:PaymentComponent},
    {path: 'admin', loadChildren: () => import('./admin/adminServices/admin.module').then(m => m.AdminModule)}
];
