import argparse
import csv
from pathlib import Path


def remove_blank_website_rows(csv_path: Path, website_column: str = "website") -> None:
    if not csv_path.exists():
        print(f"Dataset not found: {csv_path}")
        return

    tmp_path = csv_path.with_suffix(csv_path.suffix + ".tmp")

    kept = 0
    removed = 0

    with csv_path.open(newline="", encoding="utf-8") as src:
        reader = csv.reader(src)
        try:
            header = next(reader)
        except StopIteration:
            print("Dataset is empty; no rows to process.")
            return

        try:
            website_idx = header.index(website_column)
        except ValueError:
            print(f"No '{website_column}' column found in dataset header.")
            return

        with tmp_path.open("w", newline="", encoding="utf-8") as dst:
            writer = csv.writer(dst)
            writer.writerow(header)

            for row in reader:
                if len(row) <= website_idx:
                    removed += 1
                    continue

                website_value = row[website_idx].strip()
                if website_value:
                    writer.writerow(row)
                    kept += 1
                else:
                    removed += 1

    tmp_path.replace(csv_path)
    print(f"Removed {removed} row(s) with blank website.")
    print(f"Kept {kept} row(s) with website present.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Remove rows with blank website values (in-place).")
    parser.add_argument("csv_path", type=Path, help="Path to the input CSV file.")
    parser.add_argument("--website-column", default="website",
                        help="Column name containing website values (default: 'website').")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    remove_blank_website_rows(args.csv_path, website_column=args.website_column)


if __name__ == "__main__":
    main()
