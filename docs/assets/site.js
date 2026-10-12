// Keep the FAQ compact while retaining native keyboard and screen-reader support.
document.querySelectorAll('.faq details').forEach(item => {
  item.addEventListener('toggle', () => {
    if (!item.open) return;
    document.querySelectorAll('.faq details').forEach(other => {
      if (other !== item) other.open = false;
    });
  });
});
