"""A small, correct Solidity lexer.

The extractor needs tokens, not characters: a ``function`` keyword inside a string
literal, a comment, or an identifier (``myFunction``) is not a declaration, and a
regex over the raw text cannot tell the difference. This lexer produces a flat
token stream with every token's byte offset and line, so the parser can match
declarations structurally and every claim can cite ``file:line``.

It recognises exactly what the extractor consumes -- identifiers, keywords,
punctuation/operators, numeric and string literals -- and it discards comments and
whitespace. It is intentionally not a full Solidity grammar; it is the lexical
layer a declaration scanner needs, and it is honest about being nothing more.
"""

from __future__ import annotations

from dataclasses import dataclass

# Multi-character operators, longest first so greedy matching is correct.
_OPERATORS: tuple[str, ...] = (
    ">>>=", "<<=", ">>=", "**=", "...",
    ">>>", "==", "!=", "<=", ">=", "&&", "||", "++", "--",
    "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<", ">>",
    "=>", "->", ":=",
    "+", "-", "*", "/", "%", "=", "<", ">", "!", "&", "|", "^", "~",
    "?", ":", ";", ",", ".", "(", ")", "[", "]", "{", "}",
)

# Keywords that open or shape a declaration. Not exhaustive by design -- only the
# ones the declaration scanner must distinguish from identifiers.
_KEYWORDS: frozenset[str] = frozenset({
    "pragma", "solidity", "import", "contract", "interface", "library",
    "abstract", "function", "constructor", "modifier", "fallback", "receive",
    "returns", "return", "public", "private", "internal", "external",
    "pure", "view", "payable", "virtual", "override", "immutable", "constant",
    "memory", "storage", "calldata", "mapping", "struct", "enum", "event",
    "error", "emit", "require", "assert", "revert", "if", "else", "for",
    "while", "do", "break", "continue", "new", "delete", "using", "is",
    "indexed", "anonymous", "unchecked", "try", "catch", "assembly",
})


@dataclass(frozen=True)
class Token:
    kind: str          # "ident" | "keyword" | "number" | "string" | "op" | "eof"
    value: str
    line: int
    col: int
    offset: int

    def __str__(self) -> str:  # pragma: no cover - debugging aid
        return f"{self.kind}:{self.value}@{self.line}:{self.col}"


def _is_ident_start(ch: str) -> bool:
    return ch.isalpha() or ch == "_" or ch == "$"


def _is_ident_part(ch: str) -> bool:
    return ch.isalnum() or ch == "_" or ch == "$"


def lex(text: str) -> list[Token]:
    """Tokenise Solidity ``text``. Comments and whitespace are dropped.

    A lexing error (an unterminated string or block comment) raises
    :class:`ValueError` rather than silently mis-tokenising the rest of the file,
    because a silent mis-lex is exactly how a declaration scanner invents a
    function that is not there.
    """
    tokens: list[Token] = []
    i = 0
    n = len(text)
    line = 1
    col = 1

    def advance(count: int = 1) -> None:
        nonlocal i, line, col
        for _ in range(count):
            if i < n and text[i] == "\n":
                line += 1
                col = 1
            else:
                col += 1
            i += 1

    while i < n:
        ch = text[i]

        # Whitespace
        if ch in " \t\r\n":
            advance()
            continue

        # Line comment
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                advance()
            continue

        # Block comment
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            start_line = line
            advance(2)
            closed = False
            while i < n:
                if text[i] == "*" and i + 1 < n and text[i + 1] == "/":
                    advance(2)
                    closed = True
                    break
                advance()
            if not closed:
                raise ValueError(f"unterminated block comment starting at line {start_line}")
            continue

        # String literal (single or double quoted); tracks escapes.
        if ch in "\"'":
            quote = ch
            start_line, start_col, start_off = line, col, i
            buf: list[str] = []
            advance()
            closed = False
            while i < n:
                c = text[i]
                if c == "\\":
                    if i + 1 < n:
                        buf.append(text[i + 1])
                        advance(2)
                        continue
                    advance()
                    continue
                if c == quote:
                    advance()
                    closed = True
                    break
                if c == "\n":
                    break
                buf.append(c)
                advance()
            if not closed:
                raise ValueError(f"unterminated string literal starting at line {start_line}")
            tokens.append(Token("string", "".join(buf), start_line, start_col, start_off))
            continue

        # Identifier / keyword
        if _is_ident_start(ch):
            start_line, start_col, start_off = line, col, i
            buf = []
            while i < n and _is_ident_part(text[i]):
                buf.append(text[i])
                advance()
            word = "".join(buf)
            kind = "keyword" if word in _KEYWORDS else "ident"
            tokens.append(Token(kind, word, start_line, start_col, start_off))
            continue

        # Number (including hex, underscores, decimals, exponents)
        if ch.isdigit():
            start_line, start_col, start_off = line, col, i
            buf = []
            while i < n and (text[i].isalnum() or text[i] in "_."):
                # stop at a '.' that is member access on a literal like `1 ether`? keep simple
                buf.append(text[i])
                advance()
            tokens.append(Token("number", "".join(buf), start_line, start_col, start_off))
            continue

        # Operators / punctuation
        matched = None
        for op in _OPERATORS:
            if text.startswith(op, i):
                matched = op
                break
        if matched is not None:
            tokens.append(Token("op", matched, line, col, i))
            advance(len(matched))
            continue

        # Anything else: a stray character. Record it as an op so the parser can
        # skip it, but never silently drop it (dropping can merge two tokens).
        tokens.append(Token("op", ch, line, col, i))
        advance()

    tokens.append(Token("eof", "", line, col, i))
    return tokens
