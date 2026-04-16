"""
Split a CSV into rows where a column is blank vs non-blank (after strip).

Replaces the old remove_blank.py (use --column website for the same split as
that script; this tool writes two files instead of overwriting in place).
"""

import argparse
import csv
import re
from pathlib import Path


def _sanitize_for_filename(label: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9]+", "_", label.strip().lower())
    safe = re.sub(r"_+", "_", safe).strip("_")
    return safe or "col"


def derive_output_paths(csv_path: Path, column: str) -> tuple[Path, Path]:
    base = csv_path.stem
    parent = csv_path.parent
    tag = _sanitize_for_filename(column)
    blank = parent / f"{base}_{tag}_blank.csv"
    filled = parent / f"{base}_{tag}_non_blank.csv"
    return blank, filled


def split_by_blank_column(
    csv_path: Path,
    column: str = "country",
    blank_out: Path | None = None,
    non_blank_out: Path | None = None,
    only_blank: bool = False,
    only_non_blank: bool = False,
) -> None:
    if not csv_path.exists():
        print(f"Dataset not found: {csv_path}")
        return

    default_blank, default_non_blank = derive_output_paths(csv_path, column)
    out_blank = blank_out or default_blank
    out_non_blank = non_blank_out or default_non_blank

    with csv_path.open(newline="", encoding="utf-8") as src:
        reader = csv.reader(src)
        try:
            header = next(reader)
        except StopIteration:
            print("Dataset is empty; no rows to process.")
            return

        try:
            col_idx = header.index(column)
        except ValueError:
            print(f"No '{column}' column found in dataset header.")
            return

        blank_fh = None
        non_blank_fh = None
        blank_writer = None
        non_blank_writer = None

        try:
            if not only_non_blank:
                blank_fh = out_blank.open("w", newline="", encoding="utf-8")
                blank_writer = csv.writer(blank_fh)
                blank_writer.writerow(header)

            if not only_blank:
                non_blank_fh = out_non_blank.open("w", newline="", encoding="utf-8")
                non_blank_writer = csv.writer(non_blank_fh)
                non_blank_writer.writerow(header)

            blank_count = 0
            non_blank_count = 0

            for row in reader:
                if len(row) <= col_idx:
                    if blank_writer:
                        blank_writer.writerow(row)
                    blank_count += 1
                    continue

                value = row[col_idx].strip()
                if not value:
                    if blank_writer:
                        blank_writer.writerow(row)
                    blank_count += 1
                else:
                    if non_blank_writer:
                        non_blank_writer.writerow(row)
                    non_blank_count += 1
        finally:
            if blank_fh:
                blank_fh.close()
            if non_blank_fh:
                non_blank_fh.close()

    if not only_non_blank:
        print(f"Wrote {blank_count} row(s) to {out_blank.name} (blank {column})")
    if not only_blank:
        print(f"Wrote {non_blank_count} row(s) to {out_non_blank.name} (non-blank {column})")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Split a CSV by blank vs non-blank values in a column."
    )
    parser.add_argument("csv_path", type=Path, help="Path to the input CSV file.")
    parser.add_argument(
        "--column",
        default="country",
        help="Column to check (default: country). Use 'website' to mirror old remove_blank.py.",
    )
    parser.add_argument("--blank-out", type=Path, help="Output path for blank rows.")
    parser.add_argument("--non-blank-out", type=Path, help="Output path for non-blank rows.")
    parser.add_argument("--only-blank", action="store_true", help="Only write blank rows output.")
    parser.add_argument(
        "--only-non-blank",
        action="store_true",
        help="Only write non-blank rows output.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.only_blank and args.only_non_blank:
        print("Choose only one of --only-blank or --only-non-blank.")
        return

    split_by_blank_column(
        args.csv_path,
        column=args.column,
        blank_out=args.blank_out,
        non_blank_out=args.non_blank_out,
        only_blank=args.only_blank,
        only_non_blank=args.only_non_blank,
    )


if __name__ == "__main__":
    main()
