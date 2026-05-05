/* CertPortal — global JS */

// Auto-dismiss flash toasts after 6 seconds
(function () {
  const toasts = document.querySelectorAll('.flash-toast');
  toasts.forEach((toast, i) => {
    setTimeout(() => {
      toast.style.transition = 'opacity 0.4s, transform 0.4s';
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(110%)';
      setTimeout(() => toast.remove(), 420);
    }, 5000 + i * 300);
  });
})();
