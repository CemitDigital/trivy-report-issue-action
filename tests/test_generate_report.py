import json
from typing import Dict

import testfixtures

from trivy_report.report_generator import (
    Issue,
    ReportDict,
    generate_issues,
    parse_results,
)


def test_generate_report1_fastapi():
    data: ReportDict = json.load(open("tests/scans/scan1.json", "rb"))
    reports = parse_results(data, existing_issues=[])

    issues: Dict[str, Issue] = {}
    for issue in generate_issues(reports):
        issues[issue.id] = issue

    assert "fastapi-0.63.0" in issues
    issue = issues["fastapi-0.63.0"]
    assert issue.title == "Security Alert: poetry package fastapi-0.63.0"
    testfixtures.compare(
        issue.body,
        """\
# Vulnerabilities found for poetry package `fastapi-0.63.0` in `poetry.lock`

## Fixed in version
**0.65.2**

## `CVE-2021-32677` - Skill-sdk version 1.0.6 updates its dependency "FastAPI" to v0.65.2 to include a security fix.

FastAPI is a web framework for building APIs with Python 3.6+ based on standard Python type hints. FastAPI versions lower than 0.65.2 that used cookies for authentication in path operations that received JSON payloads sent by browsers were vulnerable to a Cross-Site Request Forgery (CSRF) attack. In versions lower than 0.65.2, FastAPI would try to read the request payload as JSON even if the content-type header sent was not set to application/json or a compatible JSON media type (e.g. application/geo+json). A request with a content type of text/plain containing JSON data would be accepted and the JSON data would be extracted. Requests with content type text/plain are exempt from CORS preflights, for being considered Simple requests. The browser will execute them right away including cookies, and the text content could be a JSON string that would be parsed and accepted by the FastAPI application. This is fixed in FastAPI 0.65.2. The request data is now parsed as JSON only if the content-type header is application/json or another JSON compatible media type like application/geo+json. It's best to upgrade to the latest FastAPI, but if updating is not possible then a middleware or a dependency that checks the content-type header and aborts the request if it is not application/json or another JSON compatible content type can act as a mitigating workaround.

### Severity
**HIGH**

### Primary URL
https://avd.aquasec.com/nvd/cve-2021-32677

### References
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-32677
- https://github.com/advisories/GHSA-8h2j-cgx8-6xv7
- https://github.com/tiangolo/fastapi/commit/fa7e3c996edf2d5482fff8f9d890ac2390dede4d
- https://github.com/tiangolo/fastapi/commit/fa7e3c996edf2d5482fff8f9d890ac2390dede4d (0.65.2)
- https://github.com/tiangolo/fastapi/security/advisories/GHSA-8h2j-cgx8-6xv7
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/MATAWX25TYKNEKLDMKWNLYDB34UWTROA/
- https://nvd.nist.gov/vuln/detail/CVE-2021-32677

""",
    )


def test_generate_report1_numpy():
    data: ReportDict = json.load(open("tests/scans/scan1.json", "rb"))
    reports = parse_results(data, existing_issues=[])

    issues: Dict[str, Issue] = {}
    for issue in generate_issues(reports):
        issues[issue.id] = issue

    assert "numpy-1.21.5" in issues
    issue = issues["numpy-1.21.5"]
    assert issue.title == "Security Alert: poetry package numpy-1.21.5"
    assert issue.body
    testfixtures.compare(
        issue.body,
        """\
# Vulnerabilities found for poetry package `numpy-1.21.5` in `poetry.lock`

## Fixed in version
**1.22.0**

## `CVE-2021-41496` - numpy: buffer overflow in the array_from_pyobj() in fortranobject.c

** DISPUTED ** Buffer overflow in the array_from_pyobj function of fortranobject.c in NumPy < 1.19, which allows attackers to conduct a Denial of Service attacks by carefully constructing an array with negative values. NOTE: The vendor does not agree this is a vulnerability; the negative dimensions can only be created by an already privileged user (or internally).

### Severity
**HIGH**

### Primary URL
https://avd.aquasec.com/nvd/cve-2021-41496

### References
- https://github.com/numpy/numpy/issues/19000

""",
    )


def test_generate_report1_pillow():
    data: ReportDict = json.load(open("tests/scans/scan1.json", "rb"))
    reports = parse_results(data, existing_issues=[])

    issues: Dict[str, Issue] = {}
    for issue in generate_issues(reports):
        issues[issue.id] = issue

    assert "pillow-8.2.0" in issues
    issue = issues["pillow-8.2.0"]
    assert issue.title == "Security Alert: poetry package pillow-8.2.0"
    testfixtures.compare(
        issue.body,
        """# Vulnerabilities found for poetry package `pillow-8.2.0` in `poetry.lock`

## Fixed in version
**8.3.0**

## `CVE-2021-34552` - python-pillow: Buffer overflow in image convert function

Pillow through 8.2.0 and PIL (aka Python Imaging Library) through 1.1.7 allow an attacker to pass controlled parameters directly into a convert function to trigger a buffer overflow in Convert.c.

### Severity
**CRITICAL**

### Primary URL
https://avd.aquasec.com/nvd/cve-2021-34552

### References
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-34552
- https://github.com/advisories/GHSA-7534-mm45-c74v
- https://lists.debian.org/debian-lts-announce/2021/07/msg00018.html
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/7V6LCG525ARIX6LX5QRYNAWVDD2MD2SV/
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VUGBBT63VL7G4JNOEIPDJIOC34ZFBKNJ/
- https://nvd.nist.gov/vuln/detail/CVE-2021-34552
- https://pillow.readthedocs.io/en/stable/releasenotes/8.3.0.html#buffer-overflow
- https://pillow.readthedocs.io/en/stable/releasenotes/index.html
- https://ubuntu.com/security/notices/USN-5227-1
- https://ubuntu.com/security/notices/USN-5227-2

## `CVE-2022-22815` - python-pillow: improperly initializes ImagePath.Path in path_getbbox() in path.c

path_getbbox in path.c in Pillow before 9.0.0 improperly initializes ImagePath.Path.

### Severity
**CRITICAL**

### Primary URL
https://avd.aquasec.com/nvd/cve-2022-22815

### References
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22815
- https://github.com/advisories/GHSA-pw3c-h7wp-cvhx
- https://github.com/python-pillow/Pillow/blob/c5d9223a8b5e9295d15b5a9b1ef1dae44c8499f3/src/path.c#L331
- https://lists.debian.org/debian-lts-announce/2022/01/msg00018.html
- https://nvd.nist.gov/vuln/detail/CVE-2022-22815
- https://pillow.readthedocs.io/en/stable/releasenotes/9.0.0.html#fixed-imagepath-path-array-handling
- https://ubuntu.com/security/notices/USN-5227-1
- https://ubuntu.com/security/notices/USN-5227-2
- https://www.debian.org/security/2022/dsa-5053

## `CVE-2022-22817` - python-pillow: PIL.ImageMath.eval allows evaluation of arbitrary expressions

PIL.ImageMath.eval in Pillow before 9.0.0 allows evaluation of arbitrary expressions, such as ones that use the Python exec method.

### Severity
**CRITICAL**

### Primary URL
https://avd.aquasec.com/nvd/cve-2022-22817

### References
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22817
- https://github.com/advisories/GHSA-8vj2-vxx3-667w
- https://lists.debian.org/debian-lts-announce/2022/01/msg00018.html
- https://nvd.nist.gov/vuln/detail/CVE-2022-22817
- https://pillow.readthedocs.io/en/stable/releasenotes/9.0.0.html#fixed-imagepath-path-array-handling
- https://pillow.readthedocs.io/en/stable/releasenotes/9.0.0.html#restrict-builtins-available-to-imagemath-eval
- https://ubuntu.com/security/notices/USN-5227-1
- https://ubuntu.com/security/notices/USN-5227-2
- https://www.debian.org/security/2022/dsa-5053

## `CVE-2021-23437` - python-pillow: possible ReDoS via the getrgb function

The package pillow 5.2.0 and before 8.3.2 are vulnerable to Regular Expression Denial of Service (ReDoS) via the getrgb function.

### Severity
**HIGH**

### Primary URL
https://avd.aquasec.com/nvd/cve-2021-23437

### References
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-23437
- https://github.com/advisories/GHSA-98vv-pw6r-q6q4
- https://github.com/python-pillow/Pillow/commit/9e08eb8f78fdfd2f476e1b20b7cf38683754866b
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RNSG6VFXTAROGF7ACYLMAZNQV4EJ6I2C/
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VKRCL7KKAKOXCVD7M6WC5OKFGL4L3SJT/
- https://nvd.nist.gov/vuln/detail/CVE-2021-23437
- https://pillow.readthedocs.io/en/stable/releasenotes/8.3.2.html
- https://snyk.io/vuln/SNYK-PYTHON-PILLOW-1319443
- https://ubuntu.com/security/notices/USN-5227-1
- https://ubuntu.com/security/notices/USN-5227-2

""",
    )


def test_generate_report2_fastapi():
    data: ReportDict = json.load(open("tests/scans/scan2.json", "rb"))
    reports = parse_results(data, existing_issues=[])

    issues: Dict[str, Issue] = {}
    for issue in generate_issues(reports):
        issues[issue.id] = issue

    assert "urllib3-1.26.4" in issues
    issue = issues["urllib3-1.26.4"]
    assert issue.title == "Security Alert: poetry package urllib3-1.26.4"
    testfixtures.compare(
        issue.body,
        """\
# Vulnerabilities found for poetry package `urllib3-1.26.4` in `poetry.lock`

## Fixed in version
**1.26.5**

## `CVE-2021-33503` - python-urllib3: ReDoS in the parsing of authority part of URL

An issue was discovered in urllib3 before 1.26.5. When provided with a URL containing many @ characters in the authority component, the authority regular expression exhibits catastrophic backtracking, causing a denial of service if a URL were passed as a parameter or redirected to via an HTTP redirect.

### Severity
**HIGH**

### Primary URL
https://avd.aquasec.com/nvd/cve-2021-33503

### References
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-33503
- https://github.com/advisories/GHSA-q2q7-5pp4-w6pg
- https://github.com/urllib3/urllib3/commit/2d4a3fee6de2fa45eb82169361918f759269b4ec
- https://github.com/urllib3/urllib3/security/advisories/GHSA-q2q7-5pp4-w6pg
- https://linux.oracle.com/cve/CVE-2021-33503.html
- https://linux.oracle.com/errata/ELSA-2021-4162.html
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6SCV7ZNAHS3E6PBFLJGENCDRDRWRZZ6W/
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FMUGWEAUYGGHTPPXT6YBD53WYXQGVV73/
- https://nvd.nist.gov/vuln/detail/CVE-2021-33503
- https://security.gentoo.org/glsa/202107-36
- https://www.oracle.com/security-alerts/cpuoct2021.html

""",
    )


def test_generate_report3_libexpat1():
    data: ReportDict = json.load(open("tests/scans/scan3.json", "rb"))
    reports = parse_results(data, existing_issues=[])

    issues: Dict[str, Issue] = {}
    for issue in generate_issues(reports):
        issues[issue.id] = issue

    assert "libexpat1-2.2.6-2+deb10u1" in issues
    issue = issues["libexpat1-2.2.6-2+deb10u1"]
    assert issue.title == "Security Alert: debian package libexpat1-2.2.6-2+deb10u1"
    testfixtures.compare(
        issue.body,
        """\
# Vulnerabilities found for debian package `libexpat1-2.2.6-2+deb10u1` in `python:latest (debian 10.11)`

## Fixed in version
**2.2.6-2+deb10u2**

## `CVE-2022-22822` - expat: Integer overflow in addBinding in xmlparse.c

addBinding in xmlparse.c in Expat (aka libexpat) before 2.4.3 has an integer overflow.

### Severity
**CRITICAL**

### Primary URL
https://avd.aquasec.com/nvd/cve-2022-22822

### References
- http://www.openwall.com/lists/oss-security/2022/01/17/3
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22822
- https://github.com/libexpat/libexpat/pull/539
- https://www.debian.org/security/2022/dsa-5073
- https://www.tenable.com/security/tns-2022-05

## `CVE-2022-22823` - expat: Integer overflow in build_model in xmlparse.c

build_model in xmlparse.c in Expat (aka libexpat) before 2.4.3 has an integer overflow.

### Severity
**CRITICAL**

### Primary URL
https://avd.aquasec.com/nvd/cve-2022-22823

### References
- http://www.openwall.com/lists/oss-security/2022/01/17/3
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22823
- https://github.com/libexpat/libexpat/pull/539
- https://www.debian.org/security/2022/dsa-5073
- https://www.tenable.com/security/tns-2022-05

## `CVE-2022-22824` - expat: Integer overflow in defineAttribute in xmlparse.c

defineAttribute in xmlparse.c in Expat (aka libexpat) before 2.4.3 has an integer overflow.

### Severity
**CRITICAL**

### Primary URL
https://avd.aquasec.com/nvd/cve-2022-22824

### References
- http://www.openwall.com/lists/oss-security/2022/01/17/3
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22824
- https://github.com/libexpat/libexpat/pull/539
- https://www.debian.org/security/2022/dsa-5073
- https://www.tenable.com/security/tns-2022-05

## `CVE-2022-23852` - expat: integer overflow in function XML_GetBuffer

Expat (aka libexpat) before 2.4.4 has a signed integer overflow in XML_GetBuffer, for configurations with a nonzero XML_CONTEXT_BYTES.

### Severity
**CRITICAL**

### Primary URL
https://avd.aquasec.com/nvd/cve-2022-23852

### References
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23852
- https://github.com/libexpat/libexpat/pull/550
- https://www.debian.org/security/2022/dsa-5073
- https://www.tenable.com/security/tns-2022-05

## `CVE-2022-23990` - expat: integer overflow in the doProlog function

Expat (aka libexpat) before 2.4.4 has an integer overflow in the doProlog function.

### Severity
**CRITICAL**

### Primary URL
https://avd.aquasec.com/nvd/cve-2022-23990

### References
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23990
- https://github.com/libexpat/libexpat/pull/551
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/34NXVL2RZC2YZRV74ZQ3RNFB7WCEUP7D/
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/R7FF2UH7MPXKTADYSJUAHI2Y5UHBSHUH/
- https://www.debian.org/security/2022/dsa-5073
- https://www.tenable.com/security/tns-2022-05

## `CVE-2021-45960` - expat: Large number of prefixed XML attributes on a single tag can crash libexpat

In Expat (aka libexpat) before 2.4.3, a left shift by 29 (or more) places in the storeAtts function in xmlparse.c can lead to realloc misbehavior (e.g., allocating too few bytes, or only freeing memory).

### Severity
**HIGH**

### Primary URL
https://avd.aquasec.com/nvd/cve-2021-45960

### References
- http://www.openwall.com/lists/oss-security/2022/01/17/3
- https://bugzilla.mozilla.org/show_bug.cgi?id=1217609
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45960
- https://github.com/libexpat/libexpat/issues/531
- https://github.com/libexpat/libexpat/pull/534
- https://github.com/libexpat/libexpat/pull/534/commits/0adcb34c49bee5b19bd29b16a578c510c23597ea
- https://security.netapp.com/advisory/ntap-20220121-0004/
- https://www.debian.org/security/2022/dsa-5073
- https://www.tenable.com/security/tns-2022-05

## `CVE-2021-46143` - expat: Integer overflow in doProlog in xmlparse.c

In doProlog in xmlparse.c in Expat (aka libexpat) before 2.4.3, an integer overflow exists for m_groupSize.

### Severity
**HIGH**

### Primary URL
https://avd.aquasec.com/nvd/cve-2021-46143

### References
- http://www.openwall.com/lists/oss-security/2022/01/17/3
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-46143
- https://github.com/libexpat/libexpat/issues/532
- https://github.com/libexpat/libexpat/pull/538
- https://security.netapp.com/advisory/ntap-20220121-0006/
- https://www.debian.org/security/2022/dsa-5073
- https://www.tenable.com/security/tns-2022-05

## `CVE-2022-22825` - expat: Integer overflow in lookup in xmlparse.c

lookup in xmlparse.c in Expat (aka libexpat) before 2.4.3 has an integer overflow.

### Severity
**HIGH**

### Primary URL
https://avd.aquasec.com/nvd/cve-2022-22825

### References
- http://www.openwall.com/lists/oss-security/2022/01/17/3
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22825
- https://github.com/libexpat/libexpat/pull/539
- https://www.debian.org/security/2022/dsa-5073
- https://www.tenable.com/security/tns-2022-05

## `CVE-2022-22826` - expat: Integer overflow in nextScaffoldPart in xmlparse.c

nextScaffoldPart in xmlparse.c in Expat (aka libexpat) before 2.4.3 has an integer overflow.

### Severity
**HIGH**

### Primary URL
https://avd.aquasec.com/nvd/cve-2022-22826

### References
- http://www.openwall.com/lists/oss-security/2022/01/17/3
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22826
- https://github.com/libexpat/libexpat/pull/539
- https://www.debian.org/security/2022/dsa-5073
- https://www.tenable.com/security/tns-2022-05

## `CVE-2022-22827` - expat: Integer overflow in storeAtts in xmlparse.c

storeAtts in xmlparse.c in Expat (aka libexpat) before 2.4.3 has an integer overflow.

### Severity
**HIGH**

### Primary URL
https://avd.aquasec.com/nvd/cve-2022-22827

### References
- http://www.openwall.com/lists/oss-security/2022/01/17/3
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22827
- https://github.com/libexpat/libexpat/pull/539
- https://www.debian.org/security/2022/dsa-5073
- https://www.tenable.com/security/tns-2022-05

""",
    )
