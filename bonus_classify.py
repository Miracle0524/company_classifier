import argparse
import csv
import re
from pathlib import Path


ICP_INDUSTRY_KEYWORDS = [
    # Fuel/Energy, Agriculture/Farming, Renewable Energy, Winery/Horticulture
    "fuel",
    "oil",
    "gas",
    "energy",
    "agriculture",
    "farming",
    "agtech",
    "livestock",
    "solar",
    "wind energy",
    "renewable energy",
    "clean energy",
    "winery",
    "wine and spirits",
    "horticulture",
    # E-Commerce/Retail, Digital Marketing/Advertising
    "e-commerce",
    "ecommerce",
    "e-commerce platforms",
    "retail",
    "digital marketing",
    "marketing",
    "advertising",
    "marketing automation",
    # AI/ML
    "artificial intelligence",
    "machine learning",
    "nlp",
    # Real Estate Investment
    "real estate",
    "real estate investment",
    "commercial real estate",
    # Wealth Management/Family Office
    "asset management",
    "venture capital",
    "hedge funds",
    "financial services",
    # FinTech/Banking
    "fintech",
    "banking",
    "payments",
    # Clinical Research/Labs, Research/Academic, Biotech/Pharma
    "clinical trials",
    "biotechnology",
    "pharmaceutical",
    "life science",
    "higher education",
    "neuroscience",
    "biopharma",
    "genetics",
    # Hospitality/Hotels, Small/Local Businesses
    "hospitality",
    "hotel",
    "resorts",
    "travel accommodations",
    "local business",
    "restaurants",
    "professional services",
    "home services",
    "construction",
    "automotive",
    "health care",
    "fitness",
    "beauty",
    "consulting",
    # High-value ICPs
    "broadcasting",
    "video",
    "digital media",
    "content",
    "telecommunications",
    "blockchain",
    "cryptocurrency",
    "bitcoin",
    "ethereum",
    "web3",
    "crypto",
]


def _normalize(text: str) -> str:
    text = text.strip().lower()
    text = re.sub(r"\s+", " ", text)
    return text


def derive_output_paths(csv_path: Path) -> tuple[Path, Path]:
    base = csv_path.stem
    parent = csv_path.parent
    return parent / f"{base}_bonus.csv", parent / f"{base}_non_bonus.csv"


def split_by_bonus_industry(csv_path: Path, industry_column: str = "industry") -> None:
    if not csv_path.exists():
        print(f"Dataset not found: {csv_path}")
        return

    bonus_path, non_bonus_path = derive_output_paths(csv_path)
    normalized_keywords = [_normalize(k) for k in ICP_INDUSTRY_KEYWORDS]

    with csv_path.open(newline="", encoding="utf-8") as src:
        reader = csv.reader(src)
        try:
            header = next(reader)
        except StopIteration:
            print("Dataset is empty; no rows to process.")
            return

        try:
            industry_idx = header.index(industry_column)
        except ValueError:
            print(f"No '{industry_column}' column found in dataset header.")
            return

        with bonus_path.open("w", newline="", encoding="utf-8") as bonus_fh, \
             non_bonus_path.open("w", newline="", encoding="utf-8") as non_bonus_fh:
            bonus_writer = csv.writer(bonus_fh)
            non_bonus_writer = csv.writer(non_bonus_fh)

            bonus_writer.writerow(header)
            non_bonus_writer.writerow(header)

            bonus_count = 0
            non_bonus_count = 0

            for row in reader:
                if len(row) <= industry_idx:
                    non_bonus_writer.writerow(row)
                    non_bonus_count += 1
                    continue

                industry_value = _normalize(row[industry_idx])
                if any(keyword in industry_value for keyword in normalized_keywords):
                    bonus_writer.writerow(row)
                    bonus_count += 1
                else:
                    non_bonus_writer.writerow(row)
                    non_bonus_count += 1

    print(f"Wrote {bonus_count} row(s) to {bonus_path.name} (bonus industries)")
    print(f"Wrote {non_bonus_count} row(s) to {non_bonus_path.name} (non-bonus industries)")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Split a CSV by ICP bonus industries.")
    parser.add_argument("csv_path", type=Path, help="Path to the input CSV file.")
    parser.add_argument("--industry-column", default="industry",
                        help="Column name containing industry values (default: 'industry').")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    split_by_bonus_industry(args.csv_path, industry_column=args.industry_column)


if __name__ == "__main__":
    main()
