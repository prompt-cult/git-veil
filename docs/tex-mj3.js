// MathJax 3 for the design specification's algorithm listings.
//
// The math blocks are stashed as base64 HTML comments by the
// scripts/mdbook-mathblock.py preprocessor, because the markdown renderer
// mangles TeX inside $$ blocks (array row separators and escaped braces).
// This file decodes them back into the page first, then loads MathJax 3's
// tex-svg output. Two macros the listings use are outside MathJax's bundled
// packages and are shimmed in the config rather than rewritten out of the
// spec:
//
//   \multicolumn{2}{l}{...} - column spanning is meaningless in a one-cell
//     render, so keep the cell content
//   \textsc{...} - small caps render as plain text
//
// mdBook 0.5 navigates with full page loads, so MathJax's own load-time
// typeset runs on every page; no SPA re-typeset hook is needed.
(function () {
  var PREFIX = "gv-math:";
  var comments = [];
  var walker = document.createTreeWalker(document.body, NodeFilter.SHOW_COMMENT);
  while (walker.nextNode()) {
    if ((walker.currentNode.nodeValue || "").indexOf(PREFIX) === 0) {
      comments.push(walker.currentNode);
    }
  }
  comments.forEach(function (comment) {
    var b64 = comment.nodeValue.slice(PREFIX.length).trim();
    var bytes = Uint8Array.from(atob(b64), function (c) {
      return c.charCodeAt(0);
    });
    var tex = new TextDecoder("utf-8").decode(bytes);
    comment.parentNode.replaceChild(document.createTextNode(tex), comment);
  });

  window.MathJax = {
    tex: {
      displayMath: [["$$", "$$"]],
      inlineMath: [["\\(", "\\)"]],
      macros: {
        multicolumn: ["{#3}", 3],
        textsc: ["\\text{#1}", 1],
      },
    },
    svg: { fontCache: "global" },
  };

  var script = document.createElement("script");
  script.src = "https://cdn.jsdelivr.net/npm/mathjax@3/es5/tex-svg.js";
  script.async = true;
  document.head.appendChild(script);
})();
