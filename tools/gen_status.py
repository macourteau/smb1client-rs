#!/usr/bin/env python3
"""Generate ``src/status.rs`` from the [MS-ERREF] NTSTATUS table.

The table is scraped from the published specification rather than transformed
from any existing implementation's, which is what keeps the crate free of a
third-party attribution obligation for it. See the design document's Licensing
section.

Standard library only, deliberately: an HTTP client and an HTML parser in
``Cargo.lock`` would be a permanent dependency-update subscription for a tool
that runs approximately never.

    python3 tools/gen_status.py             # rewrite src/status.rs
    python3 tools/gen_status.py --check     # regenerate and diff, writing nothing
"""

from __future__ import annotations

import argparse
import difflib
import re
import sys
import textwrap
import urllib.request
from html.parser import HTMLParser
from pathlib import Path

SPEC_URL = (
    "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/"
    "596a1078-e883-4972-9bbc-49e60bebca55"
)

# The column headings the scrape is pinned to. A page redesign that renames or
# reorders them must fail loudly rather than yield a plausible-looking subset.
EXPECTED_HEADINGS = ["Return value/code", "Description"]

# A floor, not a count: the specification gains values over time and the exact
# number is not something to pin. What it catches is a scrape that silently got
# a fragment of the table, which is the failure mode no generated test would
# notice.
MIN_ENTRIES = 1500

CODE_RE = re.compile(r"\A0x[0-9A-Fa-f]{8}\Z")
NAME_RE = re.compile(r"\A[A-Z][A-Za-z0-9_]*\Z")

# The statuses the design document turns on by name, each of which becomes an
# associated constant. Generation fails if the specification stops defining one,
# so a status the crate reasons about cannot quietly become a bare number.
#
# `STATUS_INVALID_SMB` is named by the design document too and is deliberately
# absent here: it belongs to [MS-CIFS], not to the NTSTATUS space, and its value
# collides with an unrelated [MS-ERREF] entry.
NAMED_CONSTANTS = [
    "STATUS_SUCCESS",
    "STATUS_PENDING",
    "STATUS_BUFFER_OVERFLOW",
    "STATUS_NO_MORE_FILES",
    "STATUS_INVALID_HANDLE",
    "STATUS_INVALID_PARAMETER",
    "STATUS_NO_SUCH_FILE",
    "STATUS_END_OF_FILE",
    "STATUS_MORE_PROCESSING_REQUIRED",
    "STATUS_OBJECT_NAME_NOT_FOUND",
    "STATUS_OBJECT_NAME_COLLISION",
    "STATUS_OBJECT_PATH_NOT_FOUND",
    "STATUS_SHARING_VIOLATION",
    "STATUS_FILE_IS_A_DIRECTORY",
    "STATUS_NOT_SUPPORTED",
    "STATUS_DUPLICATE_NAME",
    "STATUS_NETWORK_NAME_DELETED",
    "STATUS_DIRECTORY_NOT_EMPTY",
    "STATUS_NOT_A_DIRECTORY",
    "STATUS_USER_SESSION_DELETED",
    "STATUS_INSUFF_SERVER_RESOURCES",
    "STATUS_NOT_FOUND",
]


class ScrapeError(RuntimeError):
    """The page did not have the shape the scrape is written against."""


class TableParser(HTMLParser):
    """Collects every table row on the page as a list of cells of paragraphs.

    The specification page carries the NTSTATUS values in a single table whose
    first cell holds the code and the name as two paragraphs, and whose second
    holds the description. Anything else is a structural change the caller is
    expected to reject rather than interpret.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tables_seen = 0
        self.rows: list[tuple[bool, list[list[str]]]] = []
        self._table_depth = 0
        self._row: list[list[str]] | None = None
        self._row_is_header = False
        self._cell: list[str] | None = None
        self._para: list[str] | None = None

    def handle_starttag(self, tag: str, attrs: object) -> None:
        if tag == "table":
            self.tables_seen += 1
            self._table_depth += 1
            return
        if not self._table_depth:
            return
        if tag == "tr":
            self._row = []
            self._row_is_header = False
        elif tag in ("td", "th"):
            self._cell = []
            self._row_is_header = self._row_is_header or tag == "th"
        elif tag == "p" and self._cell is not None:
            self._close_paragraph()
            self._para = []

    def handle_endtag(self, tag: str) -> None:
        if tag == "table":
            self._table_depth = max(0, self._table_depth - 1)
            return
        if not self._table_depth:
            return
        if tag == "p":
            self._close_paragraph()
        elif tag in ("td", "th"):
            self._close_paragraph()
            if self._row is not None and self._cell is not None:
                self._row.append(self._cell)
            self._cell = None
        elif tag == "tr":
            if self._row is not None:
                self.rows.append((self._row_is_header, self._row))
            self._row = None

    def handle_data(self, data: str) -> None:
        if self._para is not None:
            self._para.append(data)

    def _close_paragraph(self) -> None:
        if self._para is None or self._cell is None:
            self._para = None
            return
        text = " ".join("".join(self._para).split())
        if text:
            self._cell.append(text)
        self._para = None


def fetch(url: str) -> str:
    """Reads the specification page, refusing anything short of a whole one."""
    request = urllib.request.Request(url, headers={"User-Agent": "smb1client-rs status generator"})
    with urllib.request.urlopen(request, timeout=120) as response:
        if response.status != 200:
            raise ScrapeError(f"{url} answered HTTP {response.status}")
        body = response.read()
        declared = response.headers.get("Content-Length")
    # A response truncated mid-transfer is the one way a scrape loses rows
    # without losing its shape, so both length and terminator are checked.
    if declared is not None and int(declared) != len(body):
        raise ScrapeError(f"read {len(body)} bytes of a declared {declared}")
    text = body.decode("utf-8")
    if not text.rstrip().endswith("</html>"):
        raise ScrapeError("page ended before its closing tag; the transfer was cut short")
    return text


def parse(page: str) -> list[tuple[int, str, str]]:
    """Extracts (code, name, description) from the page, in specification order."""
    parser = TableParser()
    parser.feed(page)
    parser.close()

    if parser.tables_seen != 1:
        raise ScrapeError(f"expected exactly one table on the page, found {parser.tables_seen}")

    headers = [cells for is_header, cells in parser.rows if is_header]
    if len(headers) != 1:
        raise ScrapeError(f"expected exactly one header row, found {len(headers)}")
    headings = [" ".join(cell) for cell in headers[0]]
    if headings != EXPECTED_HEADINGS:
        raise ScrapeError(f"column headings are {headings}, expected {EXPECTED_HEADINGS}")

    entries = []
    for index, (is_header, cells) in enumerate(parser.rows):
        if is_header:
            continue
        where = f"row {index}"
        if len(cells) != 2:
            raise ScrapeError(f"{where}: expected 2 cells, found {len(cells)}")
        if len(cells[0]) != 2:
            raise ScrapeError(f"{where}: expected code and name, found {cells[0]}")
        code, name = cells[0]
        if not CODE_RE.match(code):
            raise ScrapeError(f"{where}: {code!r} is not an eight-digit hexadecimal code")
        if not NAME_RE.match(name):
            raise ScrapeError(f"{where}: {name!r} is not a status name")
        entries.append((int(code, 16), name, " ".join(cells[1])))

    if len(entries) < MIN_ENTRIES:
        raise ScrapeError(f"only {len(entries)} entries; the table is not this small")
    return entries


def deduplicate(entries: list[tuple[int, str, str]]) -> tuple[list[tuple[int, str, str]], list[tuple[int, str]]]:
    """Keeps the first name the specification lists for each code.

    A handful of codes carry a second name — a wait-result spelling of a general
    success, and one firewall value the specification lists twice. Binary search
    needs one name per code, and the first listed is the general one.
    """
    kept: dict[int, tuple[int, str, str]] = {}
    aliases: list[tuple[int, str]] = []
    for entry in entries:
        if entry[0] in kept:
            aliases.append((entry[0], entry[1]))
        else:
            kept[entry[0]] = entry
    return sorted(kept.values()), aliases


def doc_lines(text: str, indent: str) -> list[str]:
    """Wraps specification prose into Rust doc comments.

    Square brackets are escaped because the specification uses them for message
    placeholders and rustdoc reads them as intra-doc links.
    """
    escaped = text.replace("\\", "\\\\").replace("[", "\\[").replace("]", "\\]")
    return [f"{indent}/// {line}" for line in textwrap.wrap(escaped, width=90 - len(indent))]


def render(entries: list[tuple[int, str, str]], aliases: list[tuple[int, str]]) -> str:
    by_name = {name: (code, description) for code, name, description in entries}
    missing = [name for name in NAMED_CONSTANTS if name not in by_name]
    if missing:
        raise ScrapeError(f"the specification no longer defines {', '.join(missing)}")

    out: list[str] = []
    w = out.append

    w("// @generated by tools/gen_status.py from the [MS-ERREF] specification.")
    w("// Edit the generator, not this file; `--check` holds the two in step.")
    w("")
    w("//! NT status codes, and the names the specification gives them.")
    w("//!")
    w("//! The table is scraped from [MS-ERREF] section 2.3.1 rather than transformed")
    w("//! from another implementation's table, which is what leaves the crate with no")
    w("//! third-party attribution obligation for it.")
    w("//!")
    w("//! Only the names are carried into the binary. The specification's descriptions")
    w("//! are Windows message text rather than protocol semantics, and all of them")
    w("//! together are roughly three times the weight of all the names, so they appear")
    w("//! as documentation on the named constants and nowhere a linker can see them.")
    w("//!")
    if aliases:
        spellings = ", ".join(f"`{name}` for `0x{code:08X}`" for code, name in aliases)
        for line in doc_lines(
            f"A few codes carry a second name in the specification ({spellings}). "
            "The lookup answers with the first name the specification lists.",
            "",
        ):
            w(line.replace("///", "//!"))
        w("//!")
    w(f"//! [MS-ERREF]: {SPEC_URL}")
    w("")
    w("use std::fmt;")
    w("")
    w("/// An NTSTATUS code, as it arrives in an SMB1 response header.")
    w("///")
    w("/// The crate classifies a handful of statuses and leaves the rest to the")
    w("/// caller, so the raw code stays reachable through [`NtStatus::code`]: a caller")
    w("/// must be able to match a status the crate never anticipated.")
    w("#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]")
    w("pub struct NtStatus(u32);")
    w("")
    w("impl NtStatus {")
    w("    /// Wraps a raw 32-bit status code, defined by the specification or not.")
    w("    pub const fn new(code: u32) -> Self {")
    w("        Self(code)")
    w("    }")
    w("")
    w("    /// The raw 32-bit status code.")
    w("    pub const fn code(self) -> u32 {")
    w("        self.0")
    w("    }")
    w("")
    w("    /// The specification's name for this code, or `None` where it defines none.")
    w("    pub fn name(self) -> Option<&'static str> {")
    w("        NAMES")
    w("            .binary_search_by_key(&self.0, |&(code, _)| code)")
    w("            .ok()")
    w("            .map(|index| NAMES[index].1)")
    w("    }")
    w("}")
    w("")
    w("/// The statuses this crate reasons about by name.")
    w("impl NtStatus {")
    for index, name in enumerate(NAMED_CONSTANTS):
        code, description = by_name[name]
        if index:
            w("")
        for line in doc_lines(f"`{name}` — {description}", "    "):
            w(line)
        short = name.removeprefix("STATUS_")
        w(f"    pub const {short}: Self = Self(0x{code >> 16:04X}_{code & 0xFFFF:04X});")
    w("}")
    w("")
    w("impl fmt::Display for NtStatus {")
    w("    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {")
    w("        match self.name() {")
    w('            Some(name) => write!(f, "{name} (0x{:08X})", self.0),')
    w('            None => write!(f, "unrecognized NT status 0x{:08X}", self.0),')
    w("        }")
    w("    }")
    w("}")
    w("")
    w("impl fmt::Debug for NtStatus {")
    w("    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {")
    w("        match self.name() {")
    w('            Some(name) => write!(f, "NtStatus(0x{:08X} {name})", self.0),')
    w('            None => write!(f, "NtStatus(0x{:08X})", self.0),')
    w("        }")
    w("    }")
    w("}")
    w("")
    w("/// Every code [MS-ERREF] defines, ascending, which is what [`NtStatus::name`]")
    w("/// binary-searches. A sorted slice keeps the whole table out of the instruction")
    w("/// stream and costs nothing to build at startup.")
    w("///")
    w("/// One entry per line regardless of width: the generator owns this shape, and")
    w("/// letting a formatter wrap the long names would put it and `--check` at odds.")
    w("#[rustfmt::skip]")
    w(f"static NAMES: [(u32, &str); {len(entries)}] = [")
    for code, name, _ in entries:
        w(f'    (0x{code >> 16:04X}_{code & 0xFFFF:04X}, "{name}"),')
    w("];")
    w("")
    w("#[cfg(test)]")
    w("mod tests {")
    w("    use super::NAMES;")
    w("")
    w("    // A floor rather than the count, matching the generator's own: what it")
    w("    // catches is a table that lost rows, not one the specification grew.")
    w(f"    const MINIMUM_ENTRIES: usize = {MIN_ENTRIES};")
    w("")
    w("    #[test]")
    w("    fn table_is_sorted_by_code() {")
    w("        for pair in NAMES.windows(2) {")
    w("            assert!(")
    w("                pair[0].0 <= pair[1].0,")
    w('                "0x{:08X} precedes 0x{:08X}; the binary search needs ascending codes",')
    w("                pair[0].0,")
    w("                pair[1].0,")
    w("            );")
    w("        }")
    w("    }")
    w("")
    w("    #[test]")
    w("    fn table_has_no_duplicate_codes() {")
    w("        for pair in NAMES.windows(2) {")
    w("            assert_ne!(")
    w("                pair[0].0, pair[1].0,")
    w('                "0x{:08X} appears twice, as {} and {}",')
    w("                pair[0].0, pair[0].1, pair[1].1,")
    w("            );")
    w("        }")
    w("    }")
    w("")
    w("    #[test]")
    w("    fn table_is_whole() {")
    w("        assert!(")
    w("            NAMES.len() >= MINIMUM_ENTRIES,")
    w('            "{} entries; the specification table is not this small",')
    w("            NAMES.len(),")
    w("        );")
    w("    }")
    w("}")
    w("")
    return "\n".join(out)


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    argp = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    argp.add_argument("--out", type=Path, default=root / "src" / "status.rs", help="file to write")
    argp.add_argument("--check", action="store_true", help="diff against the committed file, writing nothing")
    argp.add_argument("--url", default=SPEC_URL, help="specification page to scrape")
    argp.add_argument("--source", type=Path, help="parse this saved copy of the page instead of fetching")
    args = argp.parse_args()

    try:
        page = args.source.read_text(encoding="utf-8") if args.source else fetch(args.url)
        entries, aliases = deduplicate(parse(page))
        generated = render(entries, aliases)
    except ScrapeError as failure:
        # Loudly, and with nothing written: a scrape that quietly gets half the
        # table would pass every test the crate has.
        print(f"the specification page is not the shape this scrape expects: {failure}", file=sys.stderr)
        return 2

    print(f"{len(entries)} statuses, {len(aliases)} alternate spellings dropped", file=sys.stderr)

    if not args.check:
        args.out.write_text(generated, encoding="utf-8")
        print(f"wrote {args.out}", file=sys.stderr)
        return 0

    committed = args.out.read_text(encoding="utf-8") if args.out.exists() else ""
    if committed == generated:
        print(f"{args.out} matches the specification", file=sys.stderr)
        return 0
    sys.stdout.writelines(
        difflib.unified_diff(
            committed.splitlines(keepends=True),
            generated.splitlines(keepends=True),
            fromfile=f"{args.out} (committed)",
            tofile=f"{args.out} (generated)",
        )
    )
    print(f"{args.out} does not match the specification; regenerate it", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
