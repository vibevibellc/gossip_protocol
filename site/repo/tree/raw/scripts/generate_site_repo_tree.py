#!/usr/bin/env python3
"""Generate the static source mirror served at /repo/tree/."""

from __future__ import annotations

import html
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
MIRROR_ROOT = REPO_ROOT / "site" / "repo" / "tree"
RAW_ROOT = MIRROR_ROOT / "raw"
BLOB_ROOT = MIRROR_ROOT / "blob"
CSS_VERSION = "responsive-3"
EXCLUDED_PREFIXES = ("site/repo/tree/",)
TABLE_SEPARATOR_RE = re.compile(r"^:?-{3,}:?$")


@dataclass
class TreeNode:
    dirs: dict[str, "TreeNode"] = field(default_factory=dict)
    files: list[str] = field(default_factory=list)


def run_git(args: list[str]) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=REPO_ROOT,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    return result.stdout


def tracked_files() -> list[str]:
    paths = []
    for path in run_git(["ls-files"]).splitlines():
        if path.startswith(EXCLUDED_PREFIXES):
            continue
        if not (REPO_ROOT / path).is_file():
            continue
        paths.append(path)
    return sorted(paths)


def build_tree(paths: list[str]) -> TreeNode:
    root = TreeNode()
    for path in paths:
        parts = path.split("/")
        node = root
        for directory in parts[:-1]:
            node = node.dirs.setdefault(directory, TreeNode())
        node.files.append(parts[-1])
    return root


def format_size(size: int) -> str:
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / (1024 * 1024):.1f} MB"


def page_shell(title: str, body: str, description: str) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(title)}</title>
  <meta name="description" content="{html.escape(description)}">
  <meta property="og:title" content="{html.escape(title)}">
  <meta property="og:description" content="{html.escape(description)}">
  <meta property="og:type" content="website">
  <meta property="og:url" content="https://gossip-protocol.com/repo/tree/">
  <link rel="icon" href="/favicon.svg" type="image/svg+xml">
  <link rel="preload" href="/assets/styles.css?v={CSS_VERSION}" as="style">
  <link rel="stylesheet" href="/assets/styles.css?v={CSS_VERSION}">
</head>
<body>
  <canvas id="network-canvas" aria-hidden="true"></canvas>

  <main class="docs-page repo-browser">
    <nav class="docs-nav" aria-label="Repository mirror navigation">
      <a href="/">Home</a>
      <a href="/docs/">Docs</a>
      <a href="/repo/">Repo</a>
      <a href="/repo/tree/">Source tree</a>
      <a href="https://github.com/vibevibellc/gossip_protocol">GitHub</a>
    </nav>
{body}
  </main>

  <footer>
    <span>Gossip Protocol</span>
    <span>Peer-witnessed monitoring, compute, storage, DNS, swaps, and publishing.</span>
  </footer>

  <script src="/assets/app.js" defer></script>
</body>
</html>
"""


def breadcrumbs(parts: list[str]) -> str:
    links = ['<a href="/repo/tree/">gossip_protocol</a>']
    current: list[str] = []
    for part in parts:
        current.append(part)
        href = "/repo/tree/" + "/".join(current) + "/"
        links.append(f'<a href="{html.escape(href)}">{html.escape(part)}</a>')
    return '<div class="repo-breadcrumbs">' + '<span>/</span>'.join(links) + "</div>"


def rendered_site_link(path: str) -> str | None:
    if not path.startswith("site/"):
        return None
    relative = path.removeprefix("site/")
    if relative == "index.html":
        return "/"
    if relative.endswith("/index.html"):
        return "/" + relative.removesuffix("index.html")
    if relative.endswith(".html"):
        return "/" + relative
    return None


def directory_url(parts: list[str]) -> str:
    if not parts:
        return "/repo/tree/"
    return "/repo/tree/" + "/".join(parts) + "/"


def blob_url(path: str) -> str:
    return "/repo/tree/blob/" + path + ".html"


def raw_url(path: str) -> str:
    return "/repo/tree/raw/" + path


def safe_link_href(href: str) -> str | None:
    href = href.strip()
    allowed_prefixes = ("https://", "http://", "/", "#", "mailto:")
    if href.startswith(allowed_prefixes):
        return href
    return None


def render_inline_markdown(text: str) -> str:
    tokens: dict[str, str] = {}

    def token(value: str) -> str:
        key = f"@@MDTOKEN{len(tokens)}@@"
        tokens[key] = value
        return key

    def code_replacement(match: re.Match[str]) -> str:
        return token(f"<code>{html.escape(match.group(1))}</code>")

    def link_replacement(match: re.Match[str]) -> str:
        label = html.escape(match.group(1))
        href = safe_link_href(match.group(2))
        if href is None:
            return label
        escaped_href = html.escape(href, quote=True)
        return token(f'<a href="{escaped_href}">{label}</a>')

    def bare_url_replacement(match: re.Match[str]) -> str:
        href = match.group(1).rstrip(".,)")
        suffix = match.group(1)[len(href) :]
        escaped_href = html.escape(href, quote=True)
        escaped_label = html.escape(href)
        return token(f'<a href="{escaped_href}">{escaped_label}</a>') + suffix

    text = re.sub(r"`([^`]+)`", code_replacement, text)
    text = re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)", link_replacement, text)
    text = re.sub(r"(?<![\"'=])\b(https?://[^\s<]+)", bare_url_replacement, text)
    rendered = html.escape(text)
    rendered = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", rendered)
    for key, value in tokens.items():
        rendered = rendered.replace(key, value)
    return rendered


def split_table_row(line: str) -> list[str]:
    stripped = line.strip()
    if stripped.startswith("|"):
        stripped = stripped[1:]
    if stripped.endswith("|"):
        stripped = stripped[:-1]
    return [cell.strip() for cell in stripped.split("|")]


def is_table_separator(line: str) -> bool:
    cells = split_table_row(line)
    return bool(cells) and all(TABLE_SEPARATOR_RE.match(cell) for cell in cells)


def render_markdown_table(lines: list[str], start: int) -> tuple[str, int] | None:
    if start + 1 >= len(lines) or not is_table_separator(lines[start + 1]):
        return None
    header = split_table_row(lines[start])
    rows: list[list[str]] = []
    index = start + 2
    while index < len(lines) and lines[index].strip().startswith("|"):
        rows.append(split_table_row(lines[index]))
        index += 1
    header_html = "".join(
        f"<th>{render_inline_markdown(cell)}</th>" for cell in header
    )
    body_rows = []
    for row in rows:
        padded = row + [""] * max(0, len(header) - len(row))
        cells = "".join(
            f"<td>{render_inline_markdown(cell)}</td>" for cell in padded[: len(header)]
        )
        body_rows.append(f"<tr>{cells}</tr>")
    table = f"""<div class="repo-markdown-table-wrap">
        <table>
          <thead><tr>{header_html}</tr></thead>
          <tbody>{''.join(body_rows)}</tbody>
        </table>
      </div>"""
    return table, index


def render_markdown_document(text: str) -> str:
    lines = text.splitlines()
    output: list[str] = []
    paragraph: list[str] = []
    list_tag: str | None = None
    list_items: list[str] = []

    def flush_paragraph() -> None:
        nonlocal paragraph
        if paragraph:
            joined = " ".join(part.strip() for part in paragraph)
            output.append(f"<p>{render_inline_markdown(joined)}</p>")
            paragraph = []

    def flush_list() -> None:
        nonlocal list_tag, list_items
        if list_tag and list_items:
            items = "".join(f"<li>{item}</li>" for item in list_items)
            output.append(f"<{list_tag}>{items}</{list_tag}>")
        list_tag = None
        list_items = []

    index = 0
    while index < len(lines):
        line = lines[index]
        stripped = line.strip()

        if not stripped:
            flush_paragraph()
            flush_list()
            index += 1
            continue

        if stripped.startswith("```"):
            flush_paragraph()
            flush_list()
            fence_language = stripped.removeprefix("```").strip()
            code_lines: list[str] = []
            index += 1
            while index < len(lines) and not lines[index].strip().startswith("```"):
                code_lines.append(lines[index])
                index += 1
            if index < len(lines):
                index += 1
            language_attr = (
                f' data-language="{html.escape(fence_language, quote=True)}"'
                if fence_language
                else ""
            )
            output.append(
                f'<pre class="repo-markdown-code"{language_attr}><code>{html.escape(chr(10).join(code_lines))}</code></pre>'
            )
            continue

        table = render_markdown_table(lines, index)
        if table:
            flush_paragraph()
            flush_list()
            rendered_table, index = table
            output.append(rendered_table)
            continue

        heading = re.match(r"^(#{1,6})\s+(.+)$", stripped)
        if heading:
            flush_paragraph()
            flush_list()
            level = len(heading.group(1))
            output.append(
                f"<h{level}>{render_inline_markdown(heading.group(2))}</h{level}>"
            )
            index += 1
            continue

        unordered = re.match(r"^[-*]\s+(.+)$", stripped)
        ordered = re.match(r"^\d+\.\s+(.+)$", stripped)
        if unordered or ordered:
            flush_paragraph()
            desired_tag = "ul" if unordered else "ol"
            if list_tag != desired_tag:
                flush_list()
                list_tag = desired_tag
            item_text = (unordered or ordered).group(1)
            list_items.append(render_inline_markdown(item_text))
            index += 1
            continue

        continuation = re.match(r"^\s{2,}(.+)$", line)
        if continuation and list_tag and list_items:
            list_items[-1] += " " + render_inline_markdown(continuation.group(1))
            index += 1
            continue

        flush_list()
        paragraph.append(stripped)
        index += 1

    flush_paragraph()
    flush_list()
    return "\n".join(output)


def directory_body(parts: list[str], node: TreeNode, all_paths: list[str]) -> str:
    path_label = "/".join(parts) if parts else "Repository root"
    rows = []
    if parts:
        parent = parts[:-1]
        rows.append(
            f"""<tr>
              <td class="repo-entry-name"><a href="{html.escape(directory_url(parent))}">..</a></td>
              <td>Directory</td>
              <td></td>
              <td></td>
            </tr>"""
        )

    for name in sorted(node.dirs):
        child_parts = [*parts, name]
        rows.append(
            f"""<tr>
              <td class="repo-entry-name"><a href="{html.escape(directory_url(child_parts))}"><span class="repo-entry-icon">dir</span>{html.escape(name)}/</a></td>
              <td>Directory</td>
              <td></td>
              <td></td>
            </tr>"""
        )

    directory_path = "/".join(parts)
    for name in sorted(node.files):
        path = f"{directory_path}/{name}" if directory_path else name
        file_size = (REPO_ROOT / path).stat().st_size
        rendered = rendered_site_link(path)
        if path.endswith(".md"):
            rendered_link = (
                f'<a href="{html.escape(blob_url(path))}#rendered-markdown">Rendered</a>'
            )
        elif rendered:
            rendered_link = f'<a href="{html.escape(rendered)}">Rendered</a>'
        else:
            rendered_link = ""
        rows.append(
            f"""<tr>
              <td class="repo-entry-name"><a href="{html.escape(blob_url(path))}"><span class="repo-entry-icon">file</span>{html.escape(name)}</a></td>
              <td>File</td>
              <td>{format_size(file_size)}</td>
              <td class="repo-entry-actions"><a href="{html.escape(raw_url(path))}">Raw</a>{rendered_link}</td>
            </tr>"""
        )

    intro = ""
    if not parts:
        intro = f"""
    <section class="docs-hero repo-tree-hero">
      <p class="eyebrow">source mirror</p>
      <h1>Repository tree</h1>
      <p class="hero-text">
        A static public mirror of the source files, hosted alongside the docs. Browse directories,
        inspect files, open raw source, or jump into rendered site documentation.
      </p>
      <div class="hero-actions hero-actions-left" aria-label="Repository mirror actions">
        <a class="cta-button cta-button-primary" href="https://github.com/vibevibellc/gossip_protocol">Open GitHub</a>
        <a class="cta-button cta-button-secondary" href="/repo/tree/blob/README.md.html">View README</a>
      </div>
    </section>
    <section class="repo-quick-links" aria-label="Quick source links">
      <a href="/repo/tree/blob/README.md.html">README.md</a>
      <a href="/repo/tree/src/">src/</a>
      <a href="/repo/tree/site/docs/">site/docs/</a>
      <a href="/repo/tree/browser_runner/">browser_runner/</a>
      <a href="/docs/">Rendered docs</a>
    </section>
"""

    return f"""
    {intro}
    <section class="docs-section repo-tree-section">
      {breadcrumbs(parts)}
      <div class="repo-tree-header">
        <h2>{html.escape(path_label)}</h2>
        <span>{len(all_paths)} source files mirrored</span>
      </div>
      <div class="repo-table-wrap">
        <table class="repo-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Type</th>
              <th>Size</th>
              <th>Links</th>
            </tr>
          </thead>
          <tbody>
            {''.join(rows)}
          </tbody>
        </table>
      </div>
    </section>
"""


def file_body(path: str) -> str:
    source_path = REPO_ROOT / path
    raw = source_path.read_bytes()
    try:
        text = raw.decode("utf-8")
        is_text = True
    except UnicodeDecodeError:
        text = ""
        is_text = False
    rendered = rendered_site_link(path)
    if path.endswith(".md") and is_text:
        rendered_action = '<a class="cta-button cta-button-secondary" href="#rendered-markdown">Rendered Markdown</a>'
    elif rendered:
        rendered_action = f'<a class="cta-button cta-button-secondary" href="{html.escape(rendered)}">View rendered</a>'
    else:
        rendered_action = ""

    if is_text:
        lines = text.splitlines()
        if text.endswith("\n"):
            pass
        code_rows = []
        for number, line in enumerate(lines, start=1):
            escaped = html.escape(line) or " "
            code_rows.append(
                f"""<tr id="L{number}">
                  <td class="line-number"><a href="#L{number}">{number}</a></td>
                  <td class="code-line"><code>{escaped}</code></td>
                </tr>"""
            )
        code = f"""<div class="repo-code-wrap">
        <table class="repo-code">
          <tbody>
            {''.join(code_rows)}
          </tbody>
        </table>
      </div>"""
    else:
        code = '<p class="copy-block">Binary file. Use the raw link to download it.</p>'

    directory_parts = path.split("/")[:-1]
    markdown_view = ""
    if path.endswith(".md") and is_text:
        markdown_view = f"""
    <section class="docs-section repo-markdown-section" id="rendered-markdown">
      <h2>Rendered Markdown</h2>
      <article class="repo-markdown-body">
        {render_markdown_document(text)}
      </article>
    </section>
"""

    return f"""
    <section class="docs-hero repo-file-hero">
      <p class="eyebrow">source file</p>
      <h1>{html.escape(path)}</h1>
      <p class="hero-text">{format_size(len(raw))} mirrored from the public source tree.</p>
      <div class="hero-actions hero-actions-left" aria-label="Source file actions">
        <a class="cta-button cta-button-primary" href="{html.escape(raw_url(path))}">Open raw</a>
        <a class="cta-button cta-button-secondary" href="{html.escape(directory_url(directory_parts))}">Parent directory</a>
        {rendered_action}
      </div>
    </section>
{markdown_view}
    <section class="docs-section repo-file-section">
      <h2>Source</h2>
      {breadcrumbs(directory_parts)}
      {code}
    </section>
"""


def write_text(path: Path, contents: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents, encoding="utf-8")


def copy_raw_files(paths: list[str]) -> None:
    for path in paths:
        destination = RAW_ROOT / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPO_ROOT / path, destination)


def write_directory_pages(node: TreeNode, parts: list[str], all_paths: list[str]) -> None:
    page_path = MIRROR_ROOT.joinpath(*parts, "index.html")
    title_path = "/".join(parts) if parts else "Repository Tree"
    write_text(
        page_path,
        page_shell(
            f"{title_path} - Gossip Protocol Source Mirror",
            directory_body(parts, node, all_paths),
            "Static source tree mirror for Gossip Protocol.",
        ),
    )
    for name, child in node.dirs.items():
        write_directory_pages(child, [*parts, name], all_paths)


def write_file_pages(paths: list[str]) -> None:
    for path in paths:
        page_path = BLOB_ROOT / f"{path}.html"
        write_text(
            page_path,
            page_shell(
                f"{path} - Gossip Protocol Source Mirror",
                file_body(path),
                f"Static source viewer for {path}.",
            ),
        )


def main() -> None:
    paths = tracked_files()
    if MIRROR_ROOT.exists():
        shutil.rmtree(MIRROR_ROOT)
    tree = build_tree(paths)
    copy_raw_files(paths)
    write_directory_pages(tree, [], paths)
    write_file_pages(paths)
    print(f"mirrored {len(paths)} files into {MIRROR_ROOT.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
