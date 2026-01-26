import argparse
import csv
import re
from pathlib import Path
from typing import Iterable

DEFAULT_DATASET_PATH = Path(__file__).with_name('non_usa.csv')

AFRICA_COUNTRIES = [
    "Algeria",
    "Angola",
    "Benin",
    "Botswana",
    "Burkina Faso",
    "Burundi",
    "Cabo Verde",
    "Cameroon",
    "Central African Republic",
    "Chad",
    "Comoros",
    "Congo",
    "Democratic Republic of the Congo",
    "Djibouti",
    "Egypt",
    "Equatorial Guinea",
    "Eritrea",
    "Eswatini",
    "Ethiopia",
    "Gabon",
    "Gambia",
    "Ghana",
    "Guinea",
    "Guinea-Bissau",
    "Ivory Coast",
    "Kenya",
    "Lesotho",
    "Liberia",
    "Libya",
    "Madagascar",
    "Malawi",
    "Mali",
    "Mauritania",
    "Mauritius",
    "Morocco",
    "Mozambique",
    "Namibia",
    "Niger",
    "Nigeria",
    "Rwanda",
    "Sao Tome and Principe",
    "Senegal",
    "Seychelles",
    "Sierra Leone",
    "Somalia",
    "South Africa",
    "South Sudan",
    "Sudan",
    "Tanzania",
    "Togo",
    "Tunisia",
    "Uganda",
    "Zambia",
    "Zimbabwe",
]


def _normalize_country(value: str) -> str:
    text = value.strip().lower()
    if not text:
        return ''
    text = text.replace('-', ' ')
    text = re.sub(r'\s+', ' ', text)
    return text


def _parse_countries(raw_list: Iterable[str]) -> list[str]:
    countries: list[str] = []
    for item in raw_list:
        if not item:
            continue
        parts = [p for p in (p.strip() for p in item.split(',')) if p]
        countries.extend(parts or [item])
    return countries


def _sanitize_for_filename(label: str) -> str:
    safe = re.sub(r'[^a-zA-Z0-9]+', '_', label.strip().lower())
    safe = re.sub(r'_+', '_', safe).strip('_')
    return safe or 'country'


def derive_output_paths(csv_path: Path, label: str = 'africa') -> tuple[Path, Path]:
    base = csv_path.stem
    parent = csv_path.parent
    safe_label = _sanitize_for_filename(label)
    matched = parent / f"{base}_{safe_label}.csv"
    other = parent / f"{base}_non_{safe_label}.csv"
    return matched, other


def split_by_country(
    csv_path: Path,
    countries: Iterable[str],
    country_column: str = 'country',
    match_out: Path | None = None,
    other_out: Path | None = None,
    only_match: bool = False,
    only_other: bool = False,
) -> None:
    if not csv_path.exists():
        print(f"Dataset not found: {csv_path}")
        return

    countries_list = _parse_countries(countries)
    if not countries_list:
        print('No countries provided; nothing to do.')
        return

    normalized_targets = {_normalize_country(c) for c in countries_list if _normalize_country(c)}
    if not normalized_targets:
        print('Provided countries were empty after normalization.')
        return

    label = 'africa'
    if countries_list:
        label = countries_list[0] if len(countries_list) == 1 else 'countries'
    default_match_out, default_other_out = derive_output_paths(csv_path, label=label)
    match_path = match_out or default_match_out
    other_path = other_out or default_other_out

    with csv_path.open(newline='', encoding='utf-8') as src:
        reader = csv.reader(src)
        try:
            header = next(reader)
        except StopIteration:
            print('Dataset is empty; no rows to process.')
            return

        try:
            country_idx = header.index(country_column)
        except ValueError:
            print(f"No '{country_column}' column found in dataset header.")
            return

        match_writer = None
        other_writer = None
        match_fh = None
        other_fh = None

        try:
            if not only_other:
                match_fh = match_path.open('w', newline='', encoding='utf-8')
                match_writer = csv.writer(match_fh)
                match_writer.writerow(header)

            if not only_match:
                other_fh = other_path.open('w', newline='', encoding='utf-8')
                other_writer = csv.writer(other_fh)
                other_writer.writerow(header)

            match_count = 0
            other_count = 0

            for row in reader:
                if len(row) <= country_idx:
                    if other_writer:
                        other_writer.writerow(row)
                    other_count += 1
                    continue

                raw_value = row[country_idx]
                normalized = _normalize_country(raw_value)
                if not normalized:
                    if other_writer:
                        other_writer.writerow(row)
                    other_count += 1
                    continue

                if normalized in normalized_targets:
                    if match_writer:
                        match_writer.writerow(row)
                    match_count += 1
                else:
                    if other_writer:
                        other_writer.writerow(row)
                    other_count += 1
        finally:
            if match_fh:
                match_fh.close()
            if other_fh:
                other_fh.close()

    if not only_other:
        print(f"Wrote {match_count} row(s) to {match_path.name} (matched countries)")
    if not only_match:
        print(f"Wrote {other_count} row(s) to {other_path.name} (non-matching countries)")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Split a CSV by country.')
    parser.add_argument('csv_path', nargs='?', type=Path, default=DEFAULT_DATASET_PATH,
                        help='Path to the input CSV file.')
    parser.add_argument('--countries', nargs='*',
                        help='Countries to match (space- or comma-separated). Defaults to African countries.')
    parser.add_argument('--country-column', default='country',
                        help="Column name containing country values (default: 'country').")
    parser.add_argument('--match-out', type=Path, help='Optional output path for matching rows.')
    parser.add_argument('--other-out', type=Path, help='Optional output path for non-matching rows.')
    parser.add_argument('--only-match', action='store_true',
                        help='Only write matching rows output.')
    parser.add_argument('--only-other', action='store_true',
                        help='Only write non-matching rows output.')
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.only_match and args.only_other:
        print('Choose only one of --only-match or --only-other.')
        return

    split_by_country(
        args.csv_path,
        countries=args.countries if args.countries else AFRICA_COUNTRIES,
        country_column=args.country_column,
        match_out=args.match_out,
        other_out=args.other_out,
        only_match=args.only_match,
        only_other=args.only_other,
    )


if __name__ == '__main__':
    main()
