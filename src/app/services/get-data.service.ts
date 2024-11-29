import { Inject, Injectable, PLATFORM_ID } from '@angular/core';
import { Characters } from './characters';
import { isPlatformBrowser } from '@angular/common';

class MockLocalStorage implements Storage {
  private storage: { [key: string]: string } = {};

  get length(): number {
    return Object.keys(this.storage).length;
  }

  key(index: number): string | null {
    const keys = Object.keys(this.storage);
    return keys[index] || null;
  }

  getItem(key: string): string | null {
    return this.storage[key] || null;
  }

  setItem(key: string, value: string): void {
    this.storage[key] = value;
  }

  removeItem(key: string): void {
    delete this.storage[key];
  }

  clear(): void {
    this.storage = {};
  }
}



@Injectable({
  providedIn: 'root'
})
export class GetDataService {

  url: string = 'https://670581af031fd46a83103c90.mockapi.io/characters'
  private localStorageKey: string = 'charactersData'
  private cacheExpiration: number = 10 * 60 * 1000;
  private localStorage: Storage



  constructor(@Inject(PLATFORM_ID) private platformId: object) { 
    if (isPlatformBrowser(this.platformId)) {
      this.localStorage = window.localStorage;
    } else {
      this.localStorage = new MockLocalStorage();
    }
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
  this.localStorage.clear()
}


} 

