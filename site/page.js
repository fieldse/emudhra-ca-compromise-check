document.querySelectorAll(".cmd .copy").forEach(function (btn) {
  btn.addEventListener("click", function () {
    var code = btn.parentElement.querySelector("code");
    function flash() { btn.classList.add("done"); btn.title = "Copied"; setTimeout(function () { btn.classList.remove("done"); btn.title = "Copy"; }, 1500); }
    function selectIt() {
      var r = document.createRange(); r.selectNodeContents(code);
      var sel = window.getSelection(); sel.removeAllRanges(); sel.addRange(r);
    }
    try { navigator.clipboard.writeText(code.textContent).then(flash, selectIt); } catch (e) { selectIt(); }
  });
});
document.querySelectorAll(".code button").forEach(function (btn) {
  btn.addEventListener("click", function () {
    var pre = btn.parentElement.querySelector("pre");
    function done(label) { btn.textContent = label; setTimeout(function () { btn.textContent = "Copy"; }, 1500); }
    function selectIt() {
      var r = document.createRange(); r.selectNodeContents(pre);
      var s = window.getSelection(); s.removeAllRanges(); s.addRange(r);
      done("Selected");
    }
    try {
      navigator.clipboard.writeText(pre.innerText).then(function () { done("Copied"); }, selectIt);
    } catch (e) { selectIt(); }
  });
});
