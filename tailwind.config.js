/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        'sdap': {
          bg: '#0f0f12',
          'bg-secondary': '#18181b',
          'bg-tertiary': '#27272a',
          card: '#1f1f23',
          border: '#3f3f46',
          text: '#f4f4f5',
          'text-muted': '#a1a1aa',
          orange: '#f97316',
          'orange-dark': '#ea580c',
          'orange-light': '#fb923c',
          success: '#22c55e',
          danger: '#ef4444',
          warning: '#eab308',
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      }
    },
  },
  plugins: [],
}
