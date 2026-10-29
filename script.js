'use strict';

document.addEventListener('DOMContentLoaded', () => {
const menuToggle = document.getElementById('menuToggle');
const navLinks = document.getElementById('navLinks');
const cartButton = document.getElementById('cartButton');
const cartPanel = document.getElementById('cartPanel');
const closeCart = document.getElementById('closeCart');
const overlay = document.getElementById('overlay');
const cartCount = document.getElementById('cartCount');
const year = document.getElementById('year');

// Automatically update the copyright year.
if (year) {
year.textContent = new Date().getFullYear();
}

// Mobile navigation menu.
if (menuToggle && navLinks) {
menuToggle.addEventListener('click', () => {
const isOpen = navLinks.classList.toggle('show');
menuToggle.setAttribute('aria-expanded', String(isOpen));
menuToggle.textContent = isOpen ? '✕' : '☰';
});

navLinks.querySelectorAll('a').forEach((link) => {
  link.addEventListener('click', () => {
    navLinks.classList.remove('show');
    menuToggle.setAttribute('aria-expanded', 'false');
    menuToggle.textContent = '☰';
  });
});

}

// Open and close the shopping cart panel.
function openCart() {
if (!cartPanel || !overlay) return;

cartPanel.classList.add('open');
overlay.classList.add('show');
document.body.style.overflow = 'hidden';

if (closeCart) {
  closeCart.focus();
}

}

function closeCartPanel() {
if (!cartPanel || !overlay) return;

cartPanel.classList.remove('open');
overlay.classList.remove('show');
document.body.style.overflow = '';

if (cartButton) {
  cartButton.focus();
}

}

if (cartButton) {
cartButton.addEventListener('click', openCart);
}

if (closeCart) {
closeCart.addEventListener('click', closeCartPanel);
}

if (overlay) {
overlay.addEventListener('click', closeCartPanel);
}

// Allow the Escape key to close the cart.
document.addEventListener('keydown', (event) => {
if (event.key === 'Escape') {
closeCartPanel();

  if (navLinks && menuToggle) {
    navLinks.classList.remove('show');
    menuToggle.setAttribute('aria-expanded', 'false');
    menuToggle.textContent = '☰';
  }
}

});

// Close the cart when the screen becomes wider.
window.addEventListener('resize', () => {
if (window.innerWidth > 650 && navLinks && menuToggle) {
navLinks.classList.remove('show');
menuToggle.setAttribute('aria-expanded', 'false');
menuToggle.textContent = '☰';
}
});

// Placeholder until real products and cart functionality are connected.
if (cartCount) {
cartCount.textContent = '0';
}

console.log('AURAIC Future Store — interface loaded successfully.');
});
