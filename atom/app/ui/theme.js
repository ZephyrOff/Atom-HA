// Applique le thème choisi avant l'affichage de la page, pour éviter un éclair de la mauvaise couleur.
(function () {
  try {
    var t = localStorage.getItem('atom-theme');
    if (t === 'dark' || t === 'light') document.documentElement.setAttribute('data-theme', t);
  } catch (e) { /* stockage indisponible */ }
})();
