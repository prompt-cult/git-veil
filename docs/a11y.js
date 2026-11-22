/* Accessibility upgrades injected at runtime.
 *
 * The mdBook theme templates render the search input with a placeholder but no
 * accessible name, and ship no skip-to-content link. Both live in the
 * generated index.hbs chrome: overriding that template would freeze a full
 * copy of the shared page chrome in this repository and drift from upstream
 * at every mdBook release. Injecting the two small fixes here keeps them in
 * source control and restores them automatically at every rebuild.
 */
(function () {
  "use strict";

  var searchbar = document.getElementById("mdbook-searchbar");
  if (searchbar && !searchbar.hasAttribute("aria-label")) {
    searchbar.setAttribute("aria-label", "Search this book");
  }

  var main = document.getElementById("mdbook-content");
  if (main && !document.getElementById("skip-to-content")) {
    main.setAttribute("tabindex", "-1");
    var skip = document.createElement("a");
    skip.id = "skip-to-content";
    skip.href = "#mdbook-content";
    skip.textContent = "Skip to content";
    document.body.insertBefore(skip, document.body.firstChild);
  }
})();
