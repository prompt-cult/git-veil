#!/usr/bin/env -S uv run --script
# Runs under uv (https://docs.astral.sh/uv/): `uv run scripts/gen-plain-txt.py`
# or `./scripts/gen-plain-txt.py`. MINIMUM PYTHON: 3.9 (requires-python below).
# MINIMUM UV: any recent version. Standard library only, so the dependency
# block is empty on purpose.
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
"""Render the built mdBook print page to plain text (plain.txt).

mdBook's print page (print.html) already carries every chapter of the book
in one page, in SUMMARY.md order. This script renders that page as plain
text, so the site can publish the whole book as a single .txt file at a
stable URL. It runs right after `mdbook build` in the Pages workflow and in
the local docker build, and reads only the page mdBook just produced, so
the .txt can never drift from the HTML it comes from.

What is rendered:
  - the `<main>` content of print.html only, never the site chrome;
  - headings as text with underline rules on the top two levels, so the
    chapter structure survives in a plain file;
  - code blocks verbatim, fenced by blank lines;
  - table rows one per line with the cells joined by spaces;
  - list items as dashes or numbers, with markdown task-list checkboxes
    kept as empty boxes.

What is dropped:
  - HTML comments, which is where the base64 gv-math display-math blocks
    are stashed (see scripts/mdbook-mathblock.py), so no base64 blob ever
    reaches the text;
  - `<pre class="mermaid">` diagram sources, which are drawings, not prose;
  - images and inputs; links keep their text and lose their markup.

Known loss, accepted for now: the display-math algorithm listings in the
design chapter live only inside the dropped comments, so their bodies are
absent from the text while every heading, paragraph and code block around
them is present. The surrounding prose still describes each algorithm.

Standard library only: the same python3 runtime the Pages runner and the
docker build image already have. The script fails with a non-zero exit if
the rendered text still contains base64 blobs or markup, so a regression
is loud instead of shipping noise.
"""

import argparse
import html.parser
import pathlib
import re
import sys

# Tags that open a new block. Data between two of these is joined as one
# paragraph; the tags themselves become line breaks.
BLOCK_TAGS = frozenset(
    (
        "address", "blockquote", "dd", "div", "dl", "dt", "figure",
        "figcaption", "footer", "h1", "h2", "h3", "h4", "h5", "h6", "header",
        "hr", "li", "main", "ol", "p", "pre", "section", "summary", "table",
        "tbody", "thead", "tfoot", "tr", "ul",
    )
)
HEADING_TAGS = frozenset(("h1", "h2", "h3", "h4", "h5", "h6"))
HEADING_RULE = {"h1": "=", "h2": "-"}
# A run of alphanumerics this long only exists in the base64 gv-math blobs;
# real text, code output and key fingerprints never come close.
BASE64_RUN = re.compile(r"[A-Za-z0-9+/]{160,}")
# Anything inside these elements is dropped whole.
DROP_TAGS = frozenset(("script", "style", "svg", "template"))


class Renderer(html.parser.HTMLParser):
    """Walk print.html and collect the book text as a list of lines."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.lines: list[str] = []
        self.para: list[str] = []       # current prose line being filled
        self.in_main = False
        self.main_done = False           # set once </main> has been seen
        self.skip_stack: list[str] = []  # dropped elements being skipped
        self.pre_lines: list[str] | None = None  # verbatim pre in progress
        self.heading: tuple[str, str] | None = None
        self.list_stack: list[str] = []  # "ul" | "ol" tags
        self.list_counters: list[int] = []
        self.li_open = False
        self.in_quote = False

    # ----- line assembly -------------------------------------------------

    def _flush(self, gap: bool = False) -> None:
        line = "".join(self.para).rstrip().lstrip()
        self.para.clear()
        if line:
            if self.in_quote:
                line = "> " + line
            self.lines.append(line)
        if gap and self.lines and self.lines[-1] != "":
            self.lines.append("")

    def _text_in(self, chunk: str) -> None:
        # Flow whitespace collapses to single spaces inside a line.
        self.para.append(re.sub(r"\s+", " ", chunk))

    # ----- parser callbacks ----------------------------------------------

    def handle_starttag(self, tag, attrs):
        if self.main_done or tag == "main":
            if tag == "main" and not self.main_done:
                self.in_main = True
            return
        if not self.in_main:
            return
        if self.skip_stack or self.pre_lines is not None:
            return
        classes = frozenset(
            value for name, value in attrs if name == "class" and value
        )
        if tag in DROP_TAGS:
            self.skip_stack.append(tag)
            return
        if tag == "pre":
            if "mermaid" in classes:
                self.skip_stack.append(tag)
                return
            self._flush()
            self.pre_lines = []
            return
        if tag == "input":
            # mdBook renders markdown task-list checkboxes as a disabled
            # input: keep the empty-box cue, drop everything else about it.
            if self.li_open and dict(attrs).get("type") == "checkbox":
                self._text_in("[ ] ")
            return
        if tag == "img":
            return
        if tag == "br":
            self._flush()
            return
        if tag in HEADING_TAGS:
            self._flush()
            self.heading = (tag, "")
            return
        if tag in ("th", "td"):
            # Cells on one row are joined with a wide gap.
            if self.para:
                self._text_in("   ")
            return
        if tag in ("ul", "ol"):
            self.list_stack.append(tag)
            self.list_counters.append(0)
            return
        if tag == "li":
            self._flush()
            if self.list_stack:
                self.list_counters[-1] += 1
                indent = "    " * (len(self.list_stack) - 1)
                if self.list_stack[-1] == "ol":
                    number = self.list_counters[-1]
                    self.para.append(f"{indent}{number}. ")
                else:
                    self.para.append(f"{indent}- ")
                self.li_open = True
            return
        if tag == "blockquote":
            self._flush()
            self.in_quote = True
            return
        if tag in BLOCK_TAGS:
            self._flush()

    def handle_endtag(self, tag):
        if self.main_done or tag == "main" or not self.in_main:
            if tag == "main" and self.in_main and not self.main_done:
                self._flush()
                self.in_main = False
                self.main_done = True
            return
        if self.pre_lines is not None:
            if tag == "pre":
                block = "".join(self.pre_lines)
                self.pre_lines = None
                rows = [row.rstrip() for row in block.split("\n")]
                while rows and not rows[0].strip():
                    rows.pop(0)
                while rows and not rows[-1].strip():
                    rows.pop()
                self.lines.extend(rows)
                self._flush(gap=True)
            return
        if self.skip_stack:
            if tag == self.skip_stack[-1]:
                self.skip_stack.pop()
            return
        if tag in HEADING_TAGS and self.heading is not None:
            level, text = self.heading
            self.heading = None
            title = text.strip()
            if self.lines and self.lines[-1] != "":
                self.lines.append("")
            self.lines.append(title)
            rule = HEADING_RULE.get(level)
            if rule:
                self.lines.append(rule * max(len(title), 3))
            self.lines.append("")
            return
        if tag == "tr":
            self._flush()
            return
        if tag == "table":
            self._flush(gap=True)
            return
        if tag in ("ul", "ol"):
            if self.list_stack:
                self.list_stack.pop()
                self.list_counters.pop()
            self._flush(gap=True)
            return
        if tag == "li":
            self._flush()
            self.li_open = False
            return
        if tag == "blockquote":
            self.in_quote = False
            self._flush(gap=True)
            return
        if tag in BLOCK_TAGS:
            self._flush(gap=(tag == "p"))

    def handle_data(self, data):
        if self.main_done or not self.in_main:
            return
        if self.skip_stack:
            return
        if self.heading is not None:
            level, text = self.heading
            self.heading = (level, text + data)
            return
        if self.pre_lines is not None:
            self.pre_lines.append(data)
            return
        self._text_in(data)


def render(source: str) -> str:
    renderer = Renderer()
    renderer.feed(source)
    renderer.close()
    if not renderer.main_done:
        sys.exit("print page never closed <main>; unexpected HTML shape")
    text = "\n".join(renderer.lines)
    text = re.sub(r"\n{3,}", "\n\n", text)
    text = "\n".join(line.rstrip() for line in text.splitlines())
    return text.strip() + "\n"


def write(source_path: pathlib.Path, out_path: pathlib.Path) -> None:
    source = source_path.read_text(encoding="utf-8")
    if "<main" not in source or "</main>" not in source:
        sys.exit(f"{source_path}: no <main> content found; is this the mdBook print page?")
    text = render(source)

    problems = []
    if "gv-math" in text or "<!--" in text:
        problems.append("comment or gv-math marker leaked into the text")
    match = BASE64_RUN.search(text)
    if match:
        problems.append(f"base64 blob in text: ...{match.group(0)[:40]}...")
    if "</" in text or "<div" in text or "&amp;" in text:
        problems.append("HTML markup leaked into the text")
    if problems:
        for problem in problems:
            print(f"plain.txt check failed: {problem}", file=sys.stderr)
        raise SystemExit(1)

    out_path.write_text(text, encoding="utf-8")
    print(f"wrote {out_path} ({len(text.splitlines())} lines)")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Render the mdBook print page to a plain-text whole book."
    )
    parser.add_argument(
        "source",
        nargs="?",
        type=pathlib.Path,
        default=pathlib.Path("_book/print.html"),
        help="built print page to render (default: _book/print.html)",
    )
    parser.add_argument(
        "out",
        nargs="?",
        type=pathlib.Path,
        default=pathlib.Path("_book/plain.txt"),
        help="plain-text file to write (default: _book/plain.txt)",
    )
    args = parser.parse_args()
    write(args.source, args.out)


if __name__ == "__main__":
    main()
