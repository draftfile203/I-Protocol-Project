import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { AdminloginComponent } from '../adminlogin/adminlogin.component';
import { authGuard } from './auth.guard';
import { AdmindashboardComponent } from '../admindashboard/admindashboard.component';

const routes: Routes = [
  {path:'', component:AdminloginComponent},
  {path:'dashboard',component:AdmindashboardComponent, canActivate: [authGuard]}
];

@NgModule({
  imports: [RouterModule.forChild(routes)],
  exports: [RouterModule]
})
export class AdminRoutingModule { }
