import csv
import re
import sys
from pathlib import Path

DEFAULT_DATASET_PATH = Path(__file__).with_name('free_company_dataset.csv')


def normalize_size_label(raw: str) -> str | None:
    """
    Returns a normalized size label (e.g., '1-10', '11-50', '10001+') or None if unusable.
    Keeps the textual range as-is (trimmed, lowercased), only removing surrounding spaces.
    """
    text = raw.strip()
    if not text:
        return None

    # Must contain at least one digit to be considered a size.
    if not re.search(r'\d', text):
        return None

    return text


def sanitize_for_filename(label: str) -> str:
    safe = re.sub(r'[^a-zA-Z0-9]+', '_', label.strip().lower())
    safe = re.sub(r'_+', '_', safe).strip('_')
    return safe or 'size'


def split_by_size(csv_path: Path) -> None:
    if not csv_path.exists():
        print(f"Dataset not found: {csv_path}")
        return

    base = csv_path.stem
    parent = csv_path.parent

    writers: dict[str, csv.writer] = {}
    files = {}
    counts: dict[str, int] = {}
    skipped_missing = 0
    skipped_unusable = 0

    with csv_path.open(newline='', encoding='utf-8') as src:
        reader = csv.reader(src)
        try:
            header = next(reader)
        except StopIteration:
            print('Dataset is empty; no rows to process.')
            return

        try:
            size_idx = header.index('size')
        except ValueError:
            print("No 'size' column found in dataset header.")
            return

        def get_writer(label: str) -> csv.writer:
            if label in writers:
                return writers[label]

            filename_safe = sanitize_for_filename(label)
            path = parent / f"{base}_{filename_safe}.csv"
            fh = path.open('w', newline='', encoding='utf-8')
            writer = csv.writer(fh)
            writer.writerow(header)
            writers[label] = writer
            files[label] = fh
            counts[label] = 0
            return writer

        for row in reader:
            if len(row) <= size_idx:
                skipped_missing += 1
                continue

            label = normalize_size_label(row[size_idx])
            if label is None:
                skipped_unusable += 1
                continue

            writer = get_writer(label)
            writer.writerow(row)
            counts[label] += 1

    # Close all opened files.
    for fh in files.values():
        fh.close()

    for label, count in sorted(counts.items()):
        print(f"Wrote {count} row(s) to {base}_{sanitize_for_filename(label)}.csv (size '{label}')")

    if skipped_missing:
        print(f"Skipped {skipped_missing} row(s) missing a size value.")
    if skipped_unusable:
        print(f"Skipped {skipped_unusable} row(s) with unusable size values.")


def main() -> None:
    csv_path = DEFAULT_DATASET_PATH
    if len(sys.argv) > 1:
        csv_path = Path(sys.argv[1])

    split_by_size(csv_path)


if __name__ == '__main__':
    main()
