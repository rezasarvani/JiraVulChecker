# JiraVulChecker
Using this tool you can simply check common vulnerabilities on your target jira server<br>
# Vulnerability List
This tool will check for below vulnerabilities:
Index | Technique
--- | ---
**1** | CVE-2020-14179 (Information Disclosure)
**2** | CVE-2020-14181 (User Enumeration)
**3** | CVE-2020-14178 (Project Key Enumeration)
**4** | CVE-2019-3402 (XSS)
**5** | CVE-2019-11581 (SSTI)
**6** | CVE-2019-3396 (Path Traversal)
**7** | CVE-2019-8451 (SSRF)
**8** | CVE-2019-8449 (User Information Disclosure)
**9** | CVE-2019-3403 (User Enumeration)
**10** | CVE-2019-8442 (Sensitive Information Disclosure)
<br>

## Prerequisites
python3.6+ <br>
'requests' module --> python -m pip install requests<br>

## Tool Switches
Switch | Description
--- | ---
**-u** | Your Target Domain. Ex: http(s)://example.tld
**-c** | In order to check for CVE-2019-11581, you need to pass your JIRA session cookie to this switch
**-s** | In order to check for CVE-2019-8451, you need to pass your own server to this switch. For example your burpcollaborator address (without any https(s))
<br>

## Examples
python jiravulchecker.py -u "https://jira.example.tld"<br>
python jiravulchecker.py -u "https://jira.example.tld" -c "D56D6AB0F83239B668101A23C84A68C6"<br>
python jiravulchecker.py -u "https://jira.example.tld" -s "efxvmbbmoel8hq6up6mtnue04ot.burpcollaborator.net"<br>
