import { Component, Inject, PLATFORM_ID } from '@angular/core';
import { isPlatformBrowser } from '@angular/common';

@Component({
  selector: 'app-theme-toggle',
  standalone: true,
  templateUrl: './theme-toggle.component.html',
  styleUrls: ['./theme-toggle.component.css'],
})
export class ThemeToggleComponent {
  isDarkMode = false;

  constructor(@Inject(PLATFORM_ID) private platformId: object) {}

  toggleTheme() {
    this.isDarkMode = !this.isDarkMode;

    if (this.isDarkMode) {
      document.body.classList.add('dark-mode');  // Apply dark mode
      if (isPlatformBrowser(this.platformId)) {
        localStorage.setItem('theme', 'dark');  // Store the user's preference
      }
    } else {
      document.body.classList.remove('dark-mode'); // Remove dark mode
      if (isPlatformBrowser(this.platformId)) {
        localStorage.setItem('theme', 'light');  // Store the user's preference
      }
    }
  }

  ngOnInit() {
    if (isPlatformBrowser(this.platformId)) {
      // Check for saved theme preference in localStorage
      const savedTheme = localStorage.getItem('theme');
      if (savedTheme === 'dark') {
        this.isDarkMode = true;
        document.body.classList.add('dark-mode');  // Apply saved dark mode
      } else {
        this.isDarkMode = false;
        document.body.classList.remove('dark-mode');  // Ensure light mode is applied
      }
    }
  }
}
