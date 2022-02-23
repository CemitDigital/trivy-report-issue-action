#!/bin/bash
set -eu

if [ -z "${INPUT_FILENAME-}" ]; then
	echo "INPUT_FILENAME must be set."
	exit 1
fi

if [ -z "${GITHUB_REPOSITORY-}" ]; then
	echo "GITHUB_REPOSITORY must be set."
	exit 1
fi

if [ -z "${GITHUB_TOKEN-}" ]; then
	echo "GITHUB_TOKEN must be set."
	exit 1
fi

if [ -z "${INPUT_LABEL-}" ]; then
	echo "INPUT_LABEL must be set."
	exit 1
fi

# Parse and create issues
python -m trivy_report.report_issues "${INPUT_FILENAME-}"

# Associate issues with the specified project
if [ -n "${INPUT_PROJECT_ID-}" ]; then
	echo "Creating cards in the project $INPUT_PROJECT_ID..."
	issue_numbers=$(gh --repo "$GITHUB_REPOSITORY" issue list --label "$INPUT_LABEL" --json number --jq '.[].number')
	echo "$issue_numbers" | while read -r number; do
		issue_id=$(gh api /repos/${GITHUB_REPOSITORY}/issues/${number} --jq .id)
		gh api /projects/columns/${INPUT_PROJECT_ID}/cards -F content_id=$issue_id -F content_type="Issue"
	done
fi
