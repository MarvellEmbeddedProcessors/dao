(function () {
  function currentVersionFromPath() {
    var m = (location.pathname || "").match(/\/dao\/guides\/([^/]+)\//);
    return (m && m[1]) ? m[1] : "dao-devel";  // default on /dao/guides/
  }
  function labelFor(v) {
    if (v === "dao-devel") return "latest (dev)";
    var mm = v.match(/^dao-(.+)$/);
    return mm ? mm[1] : v;
  }
  var v = currentVersionFromPath();

  // Inform theme scripts
  if (window.DOCUMENTATION_OPTIONS) {
    window.DOCUMENTATION_OPTIONS.theme_switcher_version_match = v;
  }

  function apply() {
    try {
      var btn = document.querySelector('[id^="pst-version-switcher-button"]');
      if (!btn) return;

      // Set visible label
      btn.childNodes[0] && (btn.childNodes[0].nodeValue = labelFor(v));
      btn.textContent = labelFor(v);

      // Highlight active entry
      var menuId = btn.getAttribute("aria-controls");
      var menu = menuId && document.getElementById(menuId);
      if (menu) {
        var items = menu.querySelectorAll("a.dropdown-item");
        items.forEach(function (a) {
          var href = a.getAttribute("href") || "";
          var active = href.indexOf("/" + v + "/") !== -1;
          a.classList.toggle("active", active);
          if (active) a.setAttribute("aria-current", "true");
          else a.removeAttribute("aria-current");
        });
      }
    } catch (e) {}
  }

  document.addEventListener("DOMContentLoaded", function () {
    apply();
    setTimeout(apply, 100);
    setTimeout(apply, 600);
  });
})();