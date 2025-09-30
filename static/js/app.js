// Mobile nav toggle
document.addEventListener("DOMContentLoaded", function () {
  const navToggle = document.getElementById("navToggle");
  const mobileNav = document.getElementById("mobileNav");

  if (navToggle && mobileNav) {
    navToggle.addEventListener("click", function () {
      mobileNav.classList.toggle("open");
      navToggle.classList.toggle("open");
    });
  }

  // Submit search forms on Enter for inputs inside .search or .search-form
  document
    .querySelectorAll(".search, .search-form")
    .forEach((formContainer) => {
      formContainer.addEventListener("keypress", function (e) {
        if (e.key === "Enter") {
          e.preventDefault();
          const btn = formContainer.querySelector(
            'button[type="submit"], button'
          );
          if (btn) btn.click();
        }
      });
    });
});
