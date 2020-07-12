import argparse
import pprint

import yaraparser


def main():
    parser = argparse.ArgumentParser(
        description="Parse Yara rules into a dictionary or Python object"
    )

    parser.add_argument(
        "--file", help="File containing Yara rules to parse", type=str, required=True,
    )

    args = parser.parse_args()

    with open(args.file, "r") as infile:
        raw_rules = infile.read()

    parsed_rules = yaraparser.ParsedYaraRules()
    parsed_rules.parse_yara_rules(raw_rules)

    pprint.pprint(parsed_rules.get_yara_rules())


if __name__ == "__main__":  # pragma: no cover
    main()
