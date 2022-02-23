#!/usr/bin/env python
import argparse
import json
import sys

from trivy_report.parser import parse_issues_json_string
from trivy_report.report_generator import ReportDict, generate_issues, parse_results


def abort(text: str):
    """
    Aborts the execution by printing an error message to stderr and exiting with error code 1
    """
    print(text, file=sys.stderr)
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Parses Trivy JSON report files and prints them in Markdown format. "
            "Each report ends with a null character."
        )
    )
    parser.add_argument("file")
    parser.add_argument("--issue-json", help="JSON output of GitGub issue list")
    args = parser.parse_args()

    filename = args.file

    data: ReportDict = json.load(open(filename, "rb"))
    if not isinstance(data, dict):
        abort(f"Data in json file {filename} does not contain a dictionary")

    existing_issues = []
    if args.issue_json:
        try:
            existing_issues = parse_issues_json_string(args.issue_json)
        except TypeError as e:
            abort(f"Failed to parse GitHub issue JSON: {e}")

    try:
        reports = parse_results(data, existing_issues=existing_issues)
    except TypeError as e:
        abort(f"Failed to parse Trivy JSON report: {e}")
    issues = generate_issues(reports)

    for issue in issues:
        print(issue.title)
        print(issue.body, end="\0")


if __name__ == "__main__":
    main()
