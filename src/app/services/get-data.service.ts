import { Injectable } from '@angular/core';
import { Characters } from './characters';


@Injectable({
  providedIn: 'root'
})
export class GetDataService {

  url: string = 'https://670581af031fd46a83103c90.mockapi.io/characters'
  private localStorageKey: string = 'charactersData'
  private cacheExpiration: number = 10 * 60 * 1000;



  constructor() {
     this.clearCache()
       }

  async getData(refresh: boolean = false): Promise<Characters[]> {
     const cachedData = localStorage.getItem(this.localStorageKey)
     const cachedTime = localStorage.getItem(`${this.localStorageKey}_time`)

     if(cachedData && !refresh && cachedTime) {
      const timePassed = Date.now() - Number(cachedTime)
     if(timePassed < this.cacheExpiration){
      return JSON.parse(cachedData)
     }
     }

    const response = await fetch(this.url)
    const data = await response.json()
    

    localStorage.setItem(this.localStorageKey, JSON.stringify(data));
    localStorage.setItem(`${this.localStorageKey}_time`,String(Date.now()))
  
    return data;
  }

  clearCache(): void {
    localStorage.removeItem(this.localStorageKey)
    localStorage.removeItem(`${this.localStorageKey}_time`)
  }

}
