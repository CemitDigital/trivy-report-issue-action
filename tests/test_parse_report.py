import json
from typing import Dict

import pytest

from trivy_report.report_generator import Report, ReportDict, parse_results


@pytest.mark.parametrize(
    "report_filename,report_count",
    [
        ("tests/scans/scan1.json", 3),
        ("tests/scans/scan2.json", 1),
        ("tests/scans/scan3.json", 1),
    ],
)
def test_parse_report(report_filename: str, report_count: int):
    # Test that it is able to parse all Trivy reports into Report objects
    data: ReportDict = json.load(open(report_filename, "rb"))
    assert isinstance(data, dict)

    report_iterator = parse_results(data, existing_issues=[])
    assert report_iterator
    reports = list(report_iterator)
    assert len(reports) == report_count

    for report in reports:
        assert isinstance(report, Report)


def test_parse_report1():
    data: ReportDict = json.load(open("tests/scans/scan1.json", "rb"))
    reports: Dict[str, Report] = {}
    for report in parse_results(data, existing_issues=[]):
        reports[report.package] = report

    assert "fastapi-0.63.0" in reports
    report = reports["fastapi-0.63.0"]
    assert report.package_name == "fastapi"
    assert report.package_version == "0.63.0"
    assert report.package_fixed_version == "0.65.2"
    assert report.package_type == "poetry"
    assert report.target == "poetry.lock"
    assert len(report.vulnerabilities) == 1
    assert report.vulnerabilities[0]["VulnerabilityID"] == "CVE-2021-32677"
    assert (
        report.vulnerabilities[0]["PrimaryURL"]
        == "https://avd.aquasec.com/nvd/cve-2021-32677"
    )
    assert report.vulnerabilities[0]["FixedVersion"] == "0.65.2"

    assert "numpy-1.21.5" in reports
    report = reports["numpy-1.21.5"]
    assert report.package_name == "numpy"
    assert report.package_version == "1.21.5"
    assert report.package_fixed_version == "1.22.0"
    assert report.package_type == "poetry"
    assert report.target == "poetry.lock"
    assert len(report.vulnerabilities) == 1
    assert report.vulnerabilities[0]["VulnerabilityID"] == "CVE-2021-41496"
    assert (
        report.vulnerabilities[0]["PrimaryURL"]
        == "https://avd.aquasec.com/nvd/cve-2021-41496"
    )
    assert report.vulnerabilities[0]["FixedVersion"] == "1.22.0"

    assert "pillow-8.2.0" in reports
    report = reports["pillow-8.2.0"]
    assert report.package_name == "pillow"
    assert report.package_version == "8.2.0"
    assert report.package_fixed_version == "8.3.0"
    assert report.package_type == "poetry"
    assert report.target == "poetry.lock"
    assert len(report.vulnerabilities) == 4
    assert report.vulnerabilities[0]["VulnerabilityID"] == "CVE-2021-34552"
    assert (
        report.vulnerabilities[0]["PrimaryURL"]
        == "https://avd.aquasec.com/nvd/cve-2021-34552"
    )
    assert report.vulnerabilities[0]["FixedVersion"] == "8.3.0"


def test_parse_report2():
    data: ReportDict = json.load(open("tests/scans/scan2.json", "rb"))
    reports: Dict[str, Report] = {}
    for report in parse_results(data, existing_issues=[]):
        reports[report.package] = report

    assert "urllib3-1.26.4" in reports
    report = reports["urllib3-1.26.4"]
    assert report.package_name == "urllib3"
    assert report.package_version == "1.26.4"
    assert report.package_fixed_version == "1.26.5"
    assert report.package_type == "poetry"
    assert report.target == "poetry.lock"
    assert len(report.vulnerabilities) == 1
    assert report.vulnerabilities[0]["VulnerabilityID"] == "CVE-2021-33503"
    assert (
        report.vulnerabilities[0]["PrimaryURL"]
        == "https://avd.aquasec.com/nvd/cve-2021-33503"
    )
    assert report.vulnerabilities[0]["FixedVersion"] == "1.26.5"


def test_parse_report3():
    data: ReportDict = json.load(open("tests/scans/scan3.json", "rb"))
    reports: Dict[str, Report] = {}
    for report in parse_results(data, existing_issues=[]):
        reports[report.package] = report

    assert "libexpat1-2.2.6-2+deb10u1" in reports
    report = reports["libexpat1-2.2.6-2+deb10u1"]
    assert report.package_name == "libexpat1"
    assert report.package_version == "2.2.6-2+deb10u1"
    assert report.package_type == "debian"
    assert report.package_fixed_version == "2.2.6-2+deb10u2"
    assert report.target == "python:latest (debian 10.11)"
    assert len(report.vulnerabilities) == 10
    assert report.vulnerabilities[0]["VulnerabilityID"] == "CVE-2022-22822"
    assert (
        report.vulnerabilities[0]["PrimaryURL"]
        == "https://avd.aquasec.com/nvd/cve-2022-22822"
    )
    assert report.vulnerabilities[0]["FixedVersion"] == "2.2.6-2+deb10u2"


def test_parse_and_exclude_issues():
    # Tests that passing an issue list will exclude vulnerabilities
    data: ReportDict = json.load(open("tests/scans/scan1.json", "rb"))
    reports: Dict[str, Report] = {}
    for report in parse_results(data, existing_issues=[]):
        reports[report.package] = report

    assert {"fastapi-0.63.0", "numpy-1.21.5", "pillow-8.2.0"} == set(reports.keys())

    existing_issues = ["numpy-1.21.5"]
    reports: Dict[str, Report] = {}
    for report in parse_results(data, existing_issues=existing_issues):
        reports[report.package] = report
    assert {"fastapi-0.63.0", "pillow-8.2.0"} == set(reports.keys())

    existing_issues.append("pillow-8.2.0")
    reports: Dict[str, Report] = {}
    for report in parse_results(data, existing_issues=existing_issues):
        reports[report.package] = report
    assert {"fastapi-0.63.0"} == set(reports.keys())

    existing_issues.append("Security Alert: fastapi:0.63.0")
    reports: Dict[str, Report] = {}
    for report in parse_results(data, existing_issues=existing_issues):
        reports[report.package] = report
    assert set() == set(reports.keys())
