document.addEventListener("DOMContentLoaded", () => {
  const chips = document.querySelectorAll(".filters .chip");
  chips.forEach((chip) =>
    chip.addEventListener("click", () => {
      chips.forEach((c) => c.classList.remove("active"));
      chip.classList.add("active");
      // Placeholder for client-side filter behavior
    })
  );
});
