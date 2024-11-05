import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { AdminRoutingModule } from '../adminServices/admin-routing.module';
import { AdmindashboardComponent } from '../admindashboard/admindashboard.component';
import { AdminloginComponent } from '../adminlogin/adminlogin.component';


@NgModule({
  declarations: [
  ],
  imports: [
    CommonModule,
    AdminRoutingModule,
    AdminloginComponent,
    AdmindashboardComponent,
  ]
})
export class AdminModule { }
