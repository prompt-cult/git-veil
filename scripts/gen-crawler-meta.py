#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
"""Generate the crawler layer for the built book (mdBook output).

Everything here is derived from the build, never hand-maintained, so it
cannot drift from the HTML:

  - _book/sitemap.xml   every chapter page in SUMMARY.md order, print.html
                        last (it aggregates the same content as the
                        chapters; sitemaps.org 0.90, absolute URLs)
  - _book/llms.txt      llmstxt.org v2: title, the book description as the
                        summary, the two honest whole-book single-fetch
                        assets (print.html, plain.txt), then the chapters.
                        Nothing is invented: no per-page blurbs, no
                        llms-full.txt (print.html/plain.txt already deliver
                        the whole book in one request)
  - every built page gets <link rel="canonical">, a <meta name="description">
    and Open Graph og:title / og:type / og:url / og:description. The
    description is the book-level description from book.toml (the one
    readers already see); og:image is deliberately skipped because the only
    mark is an SVG logo and Open Graph does not support SVG. Injection is
    idempotent: a page that already carries a canonical link is left alone.

Run it after `mdbook build` (and after plain.txt if you want them
generated in the same step). Same step in the Pages workflow and
docs/Dockerfile.site keeps CI and the local preview identical.
"""

import pathlib
import re
import sys

BASE_URL = "https://prompt-cult.github.io/git-veil/"
BOOK_TOML = pathlib.Path("book.toml")
SRC_DIR = pathlib.Path("docs/src")

# Frame/self pages that are not book content.
NOT_IN_SITEMAP = {"toc.html", "404.html"}


def book_meta() -> tuple[str, str]:
    toml = BOOK_TOML.read_text(encoding="utf-8")
    title_re = re.compile(r'^title\s*=\s*"([^"]*)"', re.M)
    desc_re = re.compile(r'^description\s*=\s*"([^"]*)"', re.M)
    title_m = title_re.search(toml)
    desc_m = desc_re.search(toml)
    title = title_m.group(1) if title_m else "git-veil"
    desc = desc_m.group(1) if desc_m else ""
    return title, desc


def summary_pages() -> list[str]:
    """Chapter page names in SUMMARY.md order, e.g. index.html, solo.html."""
    summary = SRC_DIR / "SUMMARY.md"
    pages: list[str] = []
    seen: set[str] = set()
    for match in re.finditer(r"\]\(([^)#]+\.md)\)", summary.read_text(encoding="utf-8")):
        page = match.group(1).lstrip("/").removesuffix(".md") + ".html"
        if page not in seen:
            seen.add(page)
            pages.append(page)
    return pages


def built_pages(root: pathlib.Path) -> list[str]:
    pages = []
    for page in sorted(root.glob("*.html")):
        if page.name not in NOT_IN_SITEMAP:
            pages.append(page.name)
    return pages


def write_sitemap(root: pathlib.Path, order: list[str]) -> None:
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
    ]
    for page in order:
        lines.append("  <url>")
        lines.append(f"    <loc>{BASE_URL}{page}</loc>")
        lines.append("  </url>")
    lines.append("</urlset>")
    (root / "sitemap.xml").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_llms_txt(root: pathlib.Path, title: str, desc: str, order: list[str]) -> None:
    lines = [
        f"# {title}",
        "",
        f"> {desc}",
        "",
        "The whole book in one fetch:",
        "",
        f"- [Full book, one HTML page]( {BASE_URL}print.html )",
        "- [Full book, plain text]( plain.txt )",  # placeholder, fixed below
        "",
        "## Chapters",
        "",
    ]
    # fix the plain-text link to the absolute URL
    lines[lines.index("- [Full book, plain text]( plain.txt )")] = (
        f"- [Full book, plain text]( {BASE_URL}plain.txt )"
    )
    for page in order:
        if page == "print.html":
            continue
        name = re.sub(r"\.html$", "", page).replace("-", " ").capitalize()
        lines.append(f"- [{name}]( {BASE_URL}{page} )")
    (root / "llms.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def head_metas(page: str, title: str, desc: str) -> str:
    og_type = "website" if page == "index.html" else "article"
    url = f"{BASE_URL}{page}"
    return (
        f'<link rel="canonical" href="{url}">\n'
        f'<meta name="description" content="{desc}">\n'
        f'<meta property="og:title" content="{title}">\n'
        f'<meta property="og:type" content="{og_type}">\n'
        f'<meta property="og:url" content="{url}">\n'
        f'<meta property="og:description" content="{desc}">\n'
    )


def inject(root: pathlib.Path, desc: str) -> int:
    injected = 0
    for page in sorted(root.glob("*.html")):
        if page.name in NOT_IN_SITEMAP:
            continue
        html = page.read_text(encoding="utf-8")
        if 'rel="canonical"' in html:
            continue
        title_m = re.search(r"<title>([^<]*)</title>", html)
        title = title_m.group(1) if title_m else page.stem
        head_close = html.find("</head>")
        if head_close < 0:
            continue
        html = html[:head_close] + head_metas(page.name, title, desc) + html[head_close:]
        page.write_text(html, encoding="utf-8")
        injected += 1
    return injected


def main() -> int:
    root = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else pathlib.Path("_book")
    if not (root / "index.html").exists():
        print(f"error: {root} does not contain a built book (no index.html)")
        return 1
    title, desc = book_meta()
    if not desc:
        print("error: no description found in book.toml")
        return 1

    # Chapter pages from SUMMARY.md, in book order; anything else the build
    # emitted (new pages before the summary catches up) is appended, and
    # print.html always goes last as the aggregate view.
    order = [p for p in summary_pages() if (root / p).exists()]
    for page in built_pages(root):
        if page not in order:
            order.append(page)
    if "print.html" in order:
        order.remove("print.html")
    order.append("print.html")

    write_sitemap(root, order)
    write_llms_txt(root, title, desc, order)
    n = inject(root, desc)
    print(f"crawler meta: sitemap.xml with {len(order)} urls, llms.txt, "
          f"{n}* pages injected with canonical/OG".replace("*", ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
