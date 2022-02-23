import pytest

from trivy_report.parser import parse_issues_json_string


def test_parse_issue_json():
    issues = parse_issues_json_string("""[]""")
    assert issues == []

    issues = parse_issues_json_string("""[{"title": "A simple title"}]""")
    assert issues == ["A simple title"]


def test_parse_invalid_structure():
    with pytest.raises(TypeError):
        parse_issues_json_string("""["1"]""")


def test_parse_no_title():
    issues = parse_issues_json_string("""[{"id": "1"}]""")
    assert issues == []
