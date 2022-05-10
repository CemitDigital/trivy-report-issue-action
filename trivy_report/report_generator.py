

import collections
from dataclasses import dataclass
from typing import Iterator, List, Optional, OrderedDict, TypedDict

# Types for dictionaries found in JSON data


class VulnerabilityDict(TypedDict):
    RuleID: str
    Category: str
    Match: str
    StartLine: str
    Endline: str
    VulnerabilityID: str
    PkgName: str
    InstalledVersion: str
    FixedVersion: str
    Title: str
    Description: str
    Severity: str
    PrimaryURL: str
    References: List[str]


class ResultDict(TypedDict):
    Type: str
    Target: str
    Vulnerabilities: List[VulnerabilityDict]


class ReportDict(TypedDict):
    Results: List[ResultDict]


# Parsed results


@dataclass
class Vulnerability:
    vulnerability_id: str
    title: str
    pkg_name: str
    installed_version: str
    description: str
    severity: str
    url: str
    reference: str


@dataclass
class Secret:
    rule_id: str
    category: str
    severity: str
    title: str
    startline: str
    endline: str
    match: str
  

@dataclass
class Report:
    # Kind of report Secret or Vulnerability
    kind: str
    # Unique ID for report, based on package name and version
    id: str
    # Name and version of package with vulnerability
    package: str
    # Name of package
    package_name: str
    # Version for package
    package_version: str
    # Version of package the vulnerability was fixed
    package_fixed_version: Optional[str]
    # Type of package, e.g. 'poetry' or 'debian'
    package_type: str
    # The file or image that contains the vulnerability, e.g. 'poetry.lock'
    target: str
    # List of vulnerabilities found in package
    vulnerabilities: List[VulnerabilityDict]


@dataclass
class Issue:
    # Unique ID for issue, based on package name and version
    id: str
    # Vulnerability report that the issues is based on
    report: Report
    # Title of GitHub issue
    title: str
    # Body for GitHub issue
    body: str


def parse_results(data: ReportDict, existing_issues: List[str]) -> Iterator[Report]:
    """
    Parses Trivy result structure and creates a report per package/version that was found.

    :param data: The report data that was parsed from JSON file.
    :param existing_issues: List of GitHub issues, used to exclude already reported issues.
    """
    try:
        results = data["Results"]
    except Exception as e:
        raise KeyError(
            f"The JSON entry does not contain Results key. Error {e}"
        )
    if not isinstance(results, list):
        raise TypeError(
            f"The JSON entry .Results is not a list, got: {type(results).__name__}"
        )

    reports: OrderedDict[str, Issue] = collections.OrderedDict()

    for idx, result in enumerate(results):
        if not isinstance(result, dict):
            raise TypeError(
                f"The JSON entry .Results[{idx}] is not a dictionary, got: {type(result).__name__}"
            )
        if "Vulnerabilities" not in result:
            continue
        if "Secrets" not in result:
            continue
        package_type = result["Type"]
        secrets = result["Secrets"]
        vulnerabilities = result["Vulnerabilities"]
        if not isinstance(vulnerabilities, list):
            raise TypeError(
                f"The JSON entry .Results[{idx}].Vulnerabilities is not a list, got: {type(vulnerabilities).__name__}"
            )
        if not isinstance(secrets, list):
            raise TypeError(
                f"The JSON entry .Results[{idx}].Secrets is not a list, got: {type(secrets).__name__}"
            )
        for secret in secrets:
            rule_id = secret["RuleID"]
            category = secret["Category"]
            severity = secret["Severity"]
            title = secret["Title"]
            startline = secret["StartLine"]
            endline = secret["EndLine"]
            match = secret["Match"]
            has_issue = False
            for existing_issue in existing_issues:
                issue_lower = existing_issue.lower()
                if (
                    issue_lower.find(match.lower()) != -1
                    and issue_lower.find(startline.lower()) != -1
                ):
                    has_issue = True
                    break
            if has_issue:
                continue
              
            lookup_id = f"{startline}:{endline}"
             
            report = reports.get(lookup_id)
            if report is None:
                report = Report(
                    kind=result["Class"],
                    package_type=category,
                    package=rule_id,
                    id=startline,
                    target=result["Target"],
                    vulnerabilities=[secret],
                )
                reports[lookup_id] = report
            else:
                report.vulnerabilities.append(secret)
    
        for vulnerability in vulnerabilities:
            package_name = vulnerability["PkgName"]
            package_version = vulnerability["InstalledVersion"]
            package_fixed_version = vulnerability["FixedVersion"]
            package = f"{package_name}-{package_version}"
            report_id = f"{package}"
            has_issue = False
            for existing_issue in existing_issues:
                issue_lower = existing_issue.lower()
                if (
                    issue_lower.find(package_name.lower()) != -1
                    and issue_lower.find(package_version.lower()) != -1
                ):
                    has_issue = True
                    break
            if has_issue:
                continue

            lookup_id = f"{package_type}:{report_id}"

            report = reports.get(lookup_id)
            if report is None:
                report = Report(
                    kind="Vulnerability",
                    id=report_id,
                    package=package,
                    package_name=package_name,
                    package_version=package_version,
                    package_fixed_version=package_fixed_version,
                    package_type=package_type,
                    target=result["Target"],
                    vulnerabilities=[vulnerability],
                )
                reports[lookup_id] = report
            else:
                report.vulnerabilities.append(vulnerability)

    return reports.values()


def generate_issues(reports: Iterator[Report]) -> Iterator[Issue]:
    """
    Iterates all reports and renders them into GitHub issues."""
    for report in reports:
        if report.kind == "secret":
            issue_title = f"Security Alert: {report.package_type} Secret Found - {report.package}"

            issue_body = f"""\
            # Secrets found for {report.package_type} type `{report.package}` in `{report.target}`

            """
            for vulnerability_idx, vulnerability in enumerate(
                report.vulnerabilities, start=1
            ):
                issue_body += f"""\

                | Category     | Description | Severity | Line No. |   Match   |
                |:------------:|:-----------:|:--------:|:--------:|:----------|
                |{vulnerability['Category']}|{vulnerability['Title']}|{vulnerability['Severity']}|{vulnerability['Startline']}|{vulnerability['Match']}|

                """

        else:
            issue_title = f"Security Alert: {report.package_type} package {report.package}"

            issue_body = f"""\
            # Vulnerabilities found for {report.package_type} package `{report.package}` in `{report.target}`

            """
            if report.package_fixed_version:
                issue_body += f"""\
                ## Fixed in version
                **{report.package_fixed_version}**

                """
            for vulnerability_idx, vulnerability in enumerate(
                report.vulnerabilities, start=1
            ):
                reference_items = "\n".join(
                    (f"- {reference}" for reference in vulnerability["References"])
                )
                issue_body += f"""\
                ## `{vulnerability['VulnerabilityID']}` - {vulnerability['Title']}

                {vulnerability['Description']}

                ### Severity
                **{vulnerability['Severity']}**

                ### Primary URL
                {vulnerability['PrimaryURL']}

                ### References
                {reference_items}

                """
        yield Issue(report.id, report=report, title=issue_title, body=issue_body)
