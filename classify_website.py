import csv
import sys
from pathlib import Path

DEFAULT_DATASET_PATH = Path(__file__).with_name('free_company_dataset.csv')


def derive_output_paths(csv_path: Path) -> tuple[Path, Path]:
    base = csv_path.stem
    parent = csv_path.parent
    with_site = parent / f"{base}_website_present.csv"
    without_site = parent / f"{base}_website_missing.csv"
    return with_site, without_site


def split_by_website(csv_path: Path) -> None:
    if not csv_path.exists():
        print(f"Dataset not found: {csv_path}")
        return

    with_site_path, without_site_path = derive_output_paths(csv_path)

    with csv_path.open(newline='', encoding='utf-8') as src:
        reader = csv.reader(src)
        try:
            header = next(reader)
        except StopIteration:
            print('Dataset is empty; no rows to process.')
            return

        try:
            website_idx = header.index('website')
        except ValueError:
            print("No 'website' column found in dataset header.")
            return

        with with_site_path.open('w', newline='', encoding='utf-8') as with_file, \
             without_site_path.open('w', newline='', encoding='utf-8') as without_file:
            with_writer = csv.writer(with_file)
            without_writer = csv.writer(without_file)

            with_writer.writerow(header)
            without_writer.writerow(header)

            with_count = 0
            without_count = 0
            skipped_missing = 0

            for row in reader:
                if len(row) <= website_idx:
                    skipped_missing += 1
                    continue

                website_value = row[website_idx].strip()
                if website_value:
                    with_writer.writerow(row)
                    with_count += 1
                else:
                    without_writer.writerow(row)
                    without_count += 1

    print(f"Wrote {with_count} row(s) to {with_site_path.name} (website present)")
    print(f"Wrote {without_count} row(s) to {without_site_path.name} (website missing/blank)")
    if skipped_missing:
        print(f"Skipped {skipped_missing} row(s) missing a website column value.")


def main() -> None:
    csv_path = DEFAULT_DATASET_PATH
    if len(sys.argv) > 1:
        csv_path = Path(sys.argv[1])

    split_by_website(csv_path)


if __name__ == '__main__':
    main()
