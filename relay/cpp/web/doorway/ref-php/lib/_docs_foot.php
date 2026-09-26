<script>
// Copy buttons: each .copy inside a .code block copies its adjacent <pre>.
document.querySelectorAll('.code .copy').forEach(function(btn){
  btn.addEventListener('click', function(){
    var pre = btn.parentElement.querySelector('pre');
    if (!pre) return;
    var text = pre.innerText || pre.textContent || '';
    navigator.clipboard.writeText(text).then(function(){
      var old = btn.textContent;
      btn.textContent = 'Copied ✓'; btn.classList.add('ok');
      setTimeout(function(){ btn.textContent = old; btn.classList.remove('ok'); }, 1600);
    }).catch(function(){
      btn.textContent = 'Copy failed';
      setTimeout(function(){ btn.textContent = 'Copy'; }, 1600);
    });
  });
});
</script>
</body>
</html>
