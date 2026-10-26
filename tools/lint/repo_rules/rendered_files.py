"""Every file that Ansible could render as a template (FREES-159).

The ``template`` lookup and module render any file they are pointed at, whatever its
suffix, and keep a NUL byte in the output, so every tracked file outside ``.github/`` is
read as one template. Only a file whose content starts with the magic bytes of a known
binary format and whose suffix names that format is binary (``BINARY_FORMATS``); it is
still checked when it holds a template marker. A NUL byte in any other file is refused,
and so is text that is not UTF-8 (ADR 0004).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from tools.lint.repo_rules.common import Violation
from tools.lint.repo_rules.jinja_calls import (
    LEX_ERROR,
    is_possibly_template,
    template_findings,
)

if TYPE_CHECKING:
    from pathlib import Path

NUL: Final[bytes] = b"\0"
TAR_MAGIC_OFFSET: Final[int] = 257
BINARY_FORMATS: Final[tuple[tuple[frozenset[str], int, tuple[bytes, ...]], ...]] = (
    (frozenset({".png"}), 0, (b"\x89PNG\r\n\x1a\n",)),
    (frozenset({".jpg", ".jpeg"}), 0, (b"\xff\xd8\xff",)),
    (frozenset({".gif"}), 0, (b"GIF87a", b"GIF89a")),
    (frozenset({".ico"}), 0, (b"\x00\x00\x01\x00",)),
    (frozenset({".webp"}), 8, (b"WEBP",)),
    (frozenset({".gz", ".tgz"}), 0, (b"\x1f\x8b",)),
    (frozenset({".bz2"}), 0, (b"BZh",)),
    (frozenset({".xz"}), 0, (b"\xfd7zXZ\x00",)),
    (frozenset({".zst"}), 0, (b"\x28\xb5\x2f\xfd",)),
    (frozenset({".zip", ".whl", ".jar"}), 0, (b"PK\x03\x04", b"PK\x05\x06")),
    (frozenset({".tar"}), TAR_MAGIC_OFFSET, (b"ustar",)),
    (frozenset({".pdf"}), 0, (b"%PDF-",)),
    (frozenset({".woff"}), 0, (b"wOFF",)),
    (frozenset({".woff2"}), 0, (b"wOF2",)),
    (frozenset({".otf"}), 0, (b"OTTO",)),
    (frozenset({".ttf"}), 0, (b"\x00\x01\x00\x00",)),
    (frozenset({".qcow2"}), 0, (b"QFI\xfb",)),
)


def is_binary(path: Path, data: bytes) -> bool:
    """Return whether ``data`` starts like the binary format that the suffix of ``path`` names."""
    suffix = path.suffix.lower()
    return any(
        suffix in suffixes and data[offset:].startswith(magic)
        for suffixes, offset, magics in BINARY_FORMATS
        for magic in magics
    )


def rendered_file_findings(path: Path, data: bytes, *, strict: bool) -> list[Violation]:
    """Reject refused Jinja in a file that Ansible could render as a template.

    ``strict`` files are the ones that Ansible may also load value by value, as variables
    or as an inventory, so a template that does not lex is refused there. Anywhere else,
    such a file can only be rendered whole, which fails before any lookup runs.
    """
    if is_binary(path, data):
        text = data.decode("utf-8", errors="surrogateescape")
        if not is_possibly_template(text):
            return []
        strict = False
    elif NUL in data:
        return [
            Violation(
                path,
                1,
                "NUL byte in a text file is not allowed: Ansible renders the file as a "
                "template anyway, so the byte cannot mark it as binary",
            )
        ]
    else:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as error:
            return [Violation(path, 1, f"template is not valid UTF-8: {error}")]
    return sorted(
        {
            Violation(path, line, message)
            for line, message in template_findings(text)
            if strict or not message.startswith(LEX_ERROR)
        }
    )
