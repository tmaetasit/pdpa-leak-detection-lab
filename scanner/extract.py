"""Pull plain text out of the file types the scanner supports.

Version 1 handles .txt, .csv, .xlsx and .docx. Thai CSV files are often saved
as TIS-620 / Windows-874 instead of UTF-8, so text files try several encodings.
"""
from __future__ import annotations

from pathlib import Path

SUPPORTED = {".txt", ".csv", ".log", ".xlsx", ".docx"}

# Order matters: utf-8-sig strips Excel's BOM, cp874 is a superset of TIS-620.
TEXT_ENCODINGS = ("utf-8-sig", "utf-8", "cp874")


class UnsupportedFile(Exception):
    pass


def read_text_file(path: Path) -> str:
    data = path.read_bytes()
    for enc in TEXT_ENCODINGS:
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    # Last resort: keep the digits even if some Thai characters are lost.
    return data.decode("utf-8", errors="replace")


def read_xlsx(path: Path) -> str:
    from openpyxl import load_workbook

    wb = load_workbook(path, read_only=True, data_only=True)
    parts: list[str] = []
    try:
        for ws in wb.worksheets:
            for row in ws.iter_rows(values_only=True):
                parts.append("\t".join("" if v is None else _cell_text(v) for v in row))
    finally:
        wb.close()
    return "\n".join(parts)


def _cell_text(value) -> str:
    # A 13-digit ID typed into Excel as a number comes back as an int or float.
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


def read_docx(path: Path) -> str:
    from docx import Document

    doc = Document(str(path))
    parts = [p.text for p in doc.paragraphs]
    for table in doc.tables:
        for row in table.rows:
            parts.append("\t".join(cell.text for cell in row.cells))
    return "\n".join(parts)


def extract_text(path: str | Path) -> str:
    path = Path(path)
    ext = path.suffix.lower()
    if ext in {".txt", ".csv", ".log"}:
        return read_text_file(path)
    if ext == ".xlsx":
        return read_xlsx(path)
    if ext == ".docx":
        return read_docx(path)
    raise UnsupportedFile(ext)
