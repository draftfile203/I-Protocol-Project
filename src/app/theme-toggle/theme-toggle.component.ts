import { Component } from '@angular/core';

@Component({
  selector: 'app-theme-toggle',
  standalone: true,
  templateUrl: './theme-toggle.component.html',
  styleUrls: ['./theme-toggle.component.css'],
})
export class ThemeToggleComponent {
  isDarkMode = false;

  toggleTheme() {
    this.isDarkMode = !this.isDarkMode;

    if (this.isDarkMode) {
      document.body.classList.add('dark-mode');  // Apply dark mode
      localStorage.setItem('theme', 'dark');      // Store the user's preference
    } else {
      document.body.classList.remove('dark-mode'); // Remove dark mode
      localStorage.setItem('theme', 'light');     // Store the user's preference
    }
  }

  ngOnInit() {
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
