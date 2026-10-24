/** @type {import('tailwindcss').Config} */
// Token names are kept from the original build so classes written in the page's JS (text-primary, ring-primaryLight...) keep working.
module.exports = {
  content: {
    files: ['./index.html'],
    // Ignore the CSS that is inlined into the page, so deleting a class from the markup really removes its styles.
    transform: { html: (content) => content.replace(/<!-- site-css:start[\s\S]*?site-css:end -->/, '') },
  },
  // Classes that are only ever added from JavaScript.
  safelist: ['is-selected', 'is-active', 'result-ok', 'result-warn', 'result-err', 'status-done', 'status-live'],
  theme: {
    extend: {
      colors: {
        primary: '#0d422e',      // logo green (sampled from the logo artwork)
        primaryDark: '#082b1e',  // deep pine
        primaryLight: '#e6eee9', // pine mist
        accent: '#efa833',       // logo gold
        accentHover: '#f5bd5c',  // light gold
        champagne: '#f6d9a0',    // gold for text on dark
        bronze: '#8a6420',       // gold for text on light (4.9:1 on pearl)
        ink: '#10221a',          // green-black text
        surface: '#f4f6f0',      // pearl page background
        muted: '#566860',        // green-grey secondary text
      },
      fontFamily: {
        sans: ['Montserrat', 'sans-serif'],
        display: ['"Libre Caslon Display"', '"Libre Caslon Text"', 'Georgia', 'serif'],
        serif: ['"Libre Caslon Text"', 'Georgia', 'serif'],
      },
    },
  },
};
