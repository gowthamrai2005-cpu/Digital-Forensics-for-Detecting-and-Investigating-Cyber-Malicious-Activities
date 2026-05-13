function showTab(id) {
  document.querySelectorAll('.tab-content').forEach(section => {
    section.classList.remove('active');
  });
  document.getElementById(id).classList.add('active');

  document.querySelectorAll('nav li').forEach(tab => {
    tab.classList.remove('active-tab');
  });
  event.target.classList.add('active-tab');
}
