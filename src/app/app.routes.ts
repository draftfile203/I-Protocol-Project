import { Routes } from '@angular/router';
import { HomeComponent } from './home/home.component';
import { AboutComponent } from './about/about.component';
import { CharactersComponent } from './characters/characters.component';
import { DownloadComponent } from './download/download.component';
import { RegisterComponent } from './register/register.component';


export const routes: Routes = [
    {path: "", component:HomeComponent},
    {path: "about", component:AboutComponent},
    {path: "characters", component:CharactersComponent},
    {path: "download", component:DownloadComponent},
    {path: "register", component:RegisterComponent},
    {path: 'admin', loadChildren: () => import('./admin/adminServices/admin.module').then(m => m.AdminModule)}
];
