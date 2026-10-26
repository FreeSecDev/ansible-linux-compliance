from __future__ import annotations

import datetime as dt
from typing import cast

import pytest
import yaml

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    yamlsubset,
)

SEED = 20261025
DOCUMENTS = 3000
KEYS = ("alpha", "beta", "gamma", "delta", "id", "rule", "scope", "hosts", "k_1", "K2", "_x")
WORDS = (
    "alpha",
    "web01",
    "a-b",
    "x_y",
    "foo bar",
    "2026-10-01",
    "0.1.82",
    "http://e.example/p",
    "a#b",
    "caf\u00e9",
    "it's",
    "a, b",
    "[x]",
    "v1.2-rc",
    "trailing.",
)
FLOW_WORDS = ("alpha", "web01", "a-b", "x_y", "foo bar", "2026-10-01", "0.1.82", "v1")
QUOTED = ("plain", "with space", "it's", "a: b", "# hash", "yes", "1.0", "", "  padded  ", "x\\y")
BLOCK_HEADERS = ("|", "|-", "|+", ">", ">-", ">+", "| # c", ">- # c")


def stringify(value: object) -> object:
    if isinstance(value, dict):
        return {key: stringify(item) for key, item in cast("dict[str, object]", value).items()}
    if isinstance(value, list):
        return [stringify(item) for item in cast("list[object]", value)]
    if isinstance(value, dt.date):
        return value.isoformat()
    return value


class Sequence64:
    """Deterministic xorshift64* numbers for test data; not for security."""

    MASK = (1 << 64) - 1

    def __init__(self, seed: int) -> None:
        self.state = (seed or 1) & self.MASK

    def next(self) -> int:
        state = self.state
        state ^= state >> 12
        state ^= (state << 25) & self.MASK
        state ^= state >> 27
        self.state = state
        return (state * 0x2545F4914F6CDD1D) & self.MASK

    def random(self) -> float:
        return (self.next() >> 11) / float(1 << 53)

    def randint(self, low: int, high: int) -> int:
        return low + self.next() % (high - low + 1)

    def choice(self, options: tuple[str, ...]) -> str:
        return options[self.next() % len(options)]

    def sample(self, options: tuple[str, ...], count: int) -> list[str]:
        pool = list(options)
        return [pool.pop(self.next() % len(pool)) for _ in range(count)]


class Generator:
    """Seeded generator of documents in, and near, the supported YAML subset."""

    def __init__(self, seed: int) -> None:
        self.random = Sequence64(seed)

    def choice(self, options: tuple[str, ...]) -> str:
        return self.random.choice(options)

    def comment(self) -> str:
        return " # note" if self.random.random() < 0.2 else ""

    def single(self) -> str:
        return "'" + self.choice(QUOTED).replace("'", "''") + "'"

    def double(self) -> str:
        text = self.choice(QUOTED).replace("\\", "\\\\").replace('"', '\\"')
        escape = self.choice(("", "\\n", "\\t", "\\/", '\\"', "\\\\"))
        return f'"{text}{escape}"'

    def flow(self) -> str:
        count = self.random.randint(0, 3)
        items = [
            self.choice(FLOW_WORDS) if self.random.random() < 0.7 else self.single()
            for _ in range(count)
        ]
        return "[" + ", ".join(items) + "]"

    def block(self, indent: int) -> tuple[str, list[str]]:
        header = self.choice(BLOCK_HEADERS)
        content = indent + self.random.randint(1, 3)
        literal = header.startswith("|")
        lines = ["" for _ in range(self.random.randint(0, 1))]
        for _ in range(self.random.randint(1, 4)):
            extra = self.random.randint(0, 2) if literal and self.random.random() < 0.3 else 0
            lines.append(" " * (content + extra) + self.choice(WORDS))
            if self.random.random() < 0.25:
                lines.append(" " * self.random.randint(0, content))
        lines.extend(
            " " * self.random.randint(0, content) for _ in range(self.random.randint(0, 2))
        )
        return header, lines

    def scalar(self, indent: int) -> tuple[str, list[str]]:
        roll = self.random.random()
        if roll < 0.35:
            return self.choice(WORDS) + self.comment(), []
        if roll < 0.5:
            return self.single() + self.comment(), []
        if roll < 0.62:
            return self.double() + self.comment(), []
        if roll < 0.72:
            return self.flow() + self.comment(), []
        if roll < 0.77:
            return self.choice(("~", "null", "")), []
        return self.block(indent)

    def mapping(self, indent: int, depth: int) -> list[str]:
        lines: list[str] = []
        keys = self.random.sample(KEYS, self.random.randint(1, 4))
        for key in keys:
            if self.random.random() < 0.1:
                lines.append(" " * indent + "# comment")
            nested = depth < 3 and self.random.random() < 0.3
            if nested:
                lines.append(f"{' ' * indent}{key}:{self.comment()}")
                if self.random.random() < 0.5:
                    lines.extend(self.mapping(indent + 2, depth + 1))
                else:
                    offset = self.choice(("0", "2"))
                    lines.extend(self.sequence(indent + int(offset), depth + 1))
                continue
            inline, following = self.scalar(indent)
            separator = " " if inline else ""
            lines.append(f"{' ' * indent}{key}:{separator}{inline}")
            lines.extend(following)
        return lines

    def sequence(self, indent: int, depth: int) -> list[str]:
        lines: list[str] = []
        for _ in range(self.random.randint(1, 3)):
            roll = self.random.random()
            if depth < 3 and roll < 0.3:
                body = self.mapping(indent + 2, depth + 1)
                lines.append(" " * indent + "- " + body[0][indent + 2 :])
                lines.extend(body[1:])
            elif depth < 3 and roll < 0.4:
                body = self.sequence(indent + 2, depth + 1)
                lines.append(" " * indent + "- " + body[0][indent + 2 :])
                lines.extend(body[1:])
            else:
                inline, following = self.scalar(indent)
                lines.append(f"{' ' * indent}-{' ' if inline else ''}{inline}")
                lines.extend(following)
        return lines

    def document(self) -> str:
        body = self.mapping(0, 0) if self.random.random() < 0.8 else self.sequence(0, 0)
        text = "---\n" + "\n".join(body)
        return text + "\n" if self.random.random() < 0.5 else text


def corpus() -> list[str]:
    generator = Generator(SEED)
    return [generator.document() for _ in range(DOCUMENTS)]


def test_accepted_documents_load_like_pyyaml() -> None:
    accepted = 0
    for text in corpus():
        try:
            mine = yamlsubset.load(text)
        except yamlsubset.YamlSubsetError:
            continue
        accepted += 1
        assert mine == stringify(yaml.safe_load(text)), text
    assert accepted >= DOCUMENTS // 3


@pytest.mark.parametrize(
    "text",
    [
        "---\nk: |\n   x",
        "---\nk: |+\n  x\n  ",
        "---\nk: |+\n  x\n\n  ",
        "---\nk: >\n  a\n  b",
        "---\nk: |-\n  x",
        "---\nk: |+\n",
        "---\n- |\n  x",
    ],
)
def test_block_scalars_at_the_end_of_the_file(text: str) -> None:
    assert yamlsubset.load(text) == yaml.safe_load(text)
