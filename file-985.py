import re
import base64
from urllib.parse import urlparse, urljoin
from collections import namedtuple
from http.server import BaseHTTPRequestHandler
from io import BytesIO
import json
from urllib.parse import parse_qs
import argparse
import requests
import time
import threading
import random
import os
import logging

# Create a custom logging formatter
formatter = logging.Formatter('%(message)s')

# Create a custom logging handler
handler = logging.StreamHandler()
handler.setFormatter(formatter)

# Create a logger
logger = logging.getLogger('my_logger')
logger.setLevel(logging.DEBUG)
logger.addHandler(handler)

INJECTABLE_HEADERS_DEFAULT = ["User-Agent", "Referer", "Origin", "X-Forwarded-For"]
AVOID_PARAMS = ["password", "csrfmiddlewaretoken"]

class HTTPRequest(BaseHTTPRequestHandler):
    def __init__(self, request_text):
        self.__request = request_text
        request_text = request_text.replace("HTTP/2", "HTTP/1.1")
        request_text = parse_burp_request(request_text)
        if isinstance(request_text, str):
            request_text = request_text.encode("utf-8")
        self.rfile = BytesIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.is_multipart = False
        self.parse_request()

    def send_error(self, code, message):
        self.error_code = code
        self.error_message = message

    def __body(self):
        content_type = self.content_type
        body = self.rfile.read().decode("utf-8").strip()
        if content_type and "multipart/form-data" in content_type:
            self.is_multipart = True
            return body
        if content_type and content_type in [
            "application/x-www-form-urlencoded",
            "application/x-www-form-urlencoded; charset=UTF-8",
            "application/json",
            "application/json; charset=UTF-8",
            "application/json;charset=UTF-8",
            "application/json;charset=UTF-8",
        ]:
            return body
        if (
            body
            and content_type
            and content_type
            not in [
                "application/x-www-form-urlencoded",
                "application/x-www-form-urlencoded; charset=UTF-8",
                "application/json",
                "application/json; charset=UTF-8",
                "application/json;charset=UTF-8",
            ]
        ):
            return body

    @property
    def type(self):
        return self.command

    @property
    def url(self):
        url = f"{self.protocol}://{self.host}"
        if self.path:
            url = urljoin(url, self.path)
        return url

    @property
    def body(self):
        return self.__body()

    @property
    def content_type(self):
        return self.headers.get("Content-Type")

    @property
    def host(self):
        return self.headers.get("Host")

    @property
    def raw_cookies(self):
        _temp = []
        for k, v in self.headers.items():
            if k.lower() in ["cookie"]:
                _temp.append(f"{k}: {v}")
        _temp = "\n".join(_temp)
        return _temp

    @property
    def method(self):
        return self.type

    @property
    def protocol(self):
        protocol = "https"
        referer = self.headers.get("Referer")
        host = self.headers.get("Host")
        if referer and host and host in referer and "http" in referer:
            protocol = referer.split("://")[0]
        return protocol

    @property
    def raw_full_headers(self):
        _temp = []
        for k, v in self.headers.items():
            if k.lower() in ["content-length"]:
                continue
            _temp.append(f"{k}: {v}")
        _temp = "\n".join(_temp)
        return _temp

    @property
    def raw_headers(self):
        _temp = []
        for k, v in self.headers.items():
            if k.lower() in ["content-length", "cookie"]:
                continue
            _temp.append(f"{k}: {v}")
        _temp = "\n".join(_temp)
        return _temp

Struct = namedtuple("Struct", ["key", "value", "type"])

def parse_burp_request(request_text):
    _temp = ""
    regex = r"(?is)(?:<request base64=(['\"])(?P<is_base64>(?:true|false))\1><!\[CDATA\[(?P<request>(.+?))\]\]></request>)"
    mobj = re.search(regex, request_text)
    if mobj:
        is_base64 = mobj.group("is_base64") == "true"
        req = mobj.group("request")
        if is_base64:
            _temp = base64.b64decode(req).decode()
        else:
            _temp = req
    else:
        _temp = request_text
    return _temp

def extract_injection_points(url="", data="", headers="", cookies="", delimeter=""):
    _injection_points = {}
    custom_injection_in = []
    is_multipart = False
    is_json = False
    is_xml = False
    InjectionPoints = namedtuple(
        "InjectionPoints",
        [
            "custom_injection_in",
            "is_multipart",
            "is_json",
            "injection_point",
            "is_xml",
        ],
    )
    if headers:
        delimeter = "\n"
        out = [i.strip() for i in headers.split(delimeter)]
        params = [
            {
                "key": i.split(":")[0].strip(),
                "value": i.split(":")[-1].strip(),
                "type": "",
            }
            for i in out
        ]
        _temp = []
        for entry in params:
            v = entry.get("value")
            k = entry.get("key")
            PROBLEMATIC_CUSTOM_INJECTION_PATTERNS = r"(;q=[^;']+)|(\*/\*)"
            _ = re.sub(PROBLEMATIC_CUSTOM_INJECTION_PATTERNS, "", v or "")
            if "*" in _:
                _temp.append(entry)
            if k in INJECTABLE_HEADERS_DEFAULT:
                _temp.append(entry)
        if _temp:
            _injection_points.update({"HEADER": _temp})
        delimeter = ""
    if cookies:
        if not delimeter:
            if ":" in cookies:
                cookies = cookies.split(":", 1)[-1].strip()
            delimeter = ";"
        out = [i.strip() for i in cookies.split(delimeter)]
        params =params = [
    {
        "key": i.split("=")[0].strip(),
        "value": i.split("=")[-1].strip(),
        "type": "",
    }
    for i in out
    if i
]
if params:
    _injection_points.update({"COOKIE": params})
if data:
    try:
        data = json.loads(data)
        is_json = True
    except ValueError:
        pass
    if is_json:
        params = extract_json_data(data)
        if not params:
            is_json = False
    else:
        MULTIPART_RECOGNITION_REGEX = r"(?i)Content-Disposition:[^;]+;\s*name="
        mobj = re.search(MULTIPART_RECOGNITION_REGEX, data)
        if mobj:
            is_multipart = True
        XML_RECOGNITION_REGEX = r"(?s)\A\s*<[^>]+>(.+>)?\s*\Z"
        xmlmobj = re.search(XML_RECOGNITION_REGEX, data)
        if xmlmobj:
            is_xml = True
        if is_multipart:
            params = extract_multipart_formdata(data)
        elif is_xml:
            params = [
                i.groupdict()
                for i in re.finditer(
                    r"(<(?P<key>[^>]+)( [^<]*)?>)(?P<value>([^<]*))(</\2)", data
                )
            ]
            params = [
                {"key": i.get("key"), "value": i.get("value"), "type": "SOUP "}
                for i in params
            ]
        else:
            params = parse_qs(data.strip(), keep_blank_values=True)
            params = [
                {
                    "key": k.strip(),
                    "value": v[-1].strip()
                    if len(v) > 1
                    else "".join(v).strip(),  # "".join(v).replace("+", "%2b"),
                    "type": "",
                }
                for k, v in params.items()
            ]
    if params:
        _injection_points.update({"POST": params})
if url:
    parsed = urlparse(url)
    path = parsed.path
    params = parse_qs(parsed.query, keep_blank_values=True)
    params = [
        {
            "key": k.strip(),
            "value": "".join(v),
            "type": "",
        }
        for k, v in params.items()
    ]
    if not params and path and path != "/" and "*" in path:
        params = [
            {
                "key": "#1*",
                "value": "*",
                "type": "",
            }
        ]
    _injection_points.update({"GET": params})
for _type, _params in _injection_points.items():
    for entry in _params:
        key = entry.get("key")
        value = entry.get("value")
        if value and "*" in value:
            custom_injection_in.append(_type)
        if key and "*" in key and key != "#1*":
            custom_injection_in.append(_type)
injection_point = {}
for _type, _params in _injection_points.items():
    _ = []
    for entry in _params:
        p = Struct(**entry)
        if p.key in AVOID_PARAMS:
            continue
        _.append(p)
    injection_point.update({_type: _})
sorted_injection_points = collections.OrderedDict()
sorted_injection_points.update(
    {
        "GET": injection_point.get("GET", []),
        "POST": injection_point.get("POST", []),
        "COOKIE": injection_point.get("COOKIE", []),
        "HEADER": injection_point.get("HEADER", []),
    }
)
sorted_injection_points = dict(sorted_injection_points)
_temp = InjectionPoints(
    custom_injection_in=list(set(custom_injection_in)),
    is_multipart=is_multipart,
    is_json=is_json,
    injection_point=sorted_injection_points,
    is_xml=is_xml,
)
return _temp

def extract_json_data(data):
    try:
        json_data = json.loads(data)
    except ValueError:
        return None
    params = []
    for key, value in json_data.items():
        if isinstance(value, dict):
            params.extend(extract_json_data(value))
        else:
            params.append({"key": key, "value": value, "type": ""})
    return params

def extract_multipart_formdata(data):
    boundary = None
    for line in data.splitlines():
        if line.startswith(b"--"):
            boundary = line.strip()
            break
    if not boundary:
        return []
    params = []
    current_key = None
    current_value = []
    for line in data.splitlines():
        if line == boundary:
            continue
        if line.startswith(b"Content-Disposition:"):
            match = re.search(r"filename=\"(.*)\"", line)
            if match:
                filename = match.group(1)
                current_key =

filename = match.group(1)
                current_key = filename
                continue
            match = re.search(r"name=\"(.*)\"", line)
            if match:
                current_key = match.group(1)
                continue
        if line == b"":
            if current_key:
                params.append(
                    {"key": current_key, "value": b"".join(current_value).decode("utf-8"), "type": ""}
                )
            current_key = None
            current_value = []
        else:
            current_value.append(line)

    return params

def perform_request(url, payload, cookie, user_agent, verbose):
    url_with_payload = url.replace("*", payload)
    start_time = time.time()
    headers = {}
    if cookie:
        headers["Cookie"] = cookie
    if user_agent:
        headers["User-Agent"] = user_agent

    try:
        response = requests.get(url_with_payload, headers=headers)
        response_code = response.status_code
        response_headers = response.headers
        response_body = response.text
    except requests.RequestException as e:
        return True, url_with_payload, time.time() - start_time, str(e), 0, {}, ""

    response_time = time.time() - start_time

    if verbose:
        logger.debug(f"---------------- Request -------------")
        logger.debug(f"--------------------------------------")
        logger.debug(f"1) Status Code: {response_code}")
        logger.debug(f"2) URL: {url}")
        logger.debug(f"3) URL with Payload: {url_with_payload}")
        logger.debug(f"4) Payload: {payload}")
        logger.debug(f"5) Cookie: {cookie}")
        logger.debug(f"6) User-Agent: {user_agent}")
        logger.debug(f"7) Headers: {headers}")
        logger.debug(f"----------------------------------------")

    if 200 <= response_code < 300:
        return True, url_with_payload, response_time, "", response_code, response_headers, response_body
    return False, url_with_payload, response_time, f"HTTP status code: {response_code}", response_code, response_headers, response_body

def is_firewall_detected(response_code, response_time, response_headers, response_body):
    waf_headers = ["X-CDN", "X-Cache", "X-WAF", "X-Web-Firewall", "X-Content-Type-Options"]
    if any(header in response_headers for header in waf_headers):
        return True

    blocked_codes = [403, 429, 451]
    if response_code in blocked_codes:
        return True

    if response_time > 500:
        return True

    blocked_keywords = ["blocked", "denied", "access denied"]
    if any(keyword in response_body.lower() for keyword in blocked_keywords):
        return True

    known_waf_indicators = {
        "Cloudflare": ["X-CDN", "X-Cache"],
        "Akamai": ["X-Akamai-Origin-Hop", "X-Akamai-Request-ID"],
        "Incapsula": ["X-CDN", "X-Incapsula-Response"],
    }
    for waf, indicators in known_waf_indicators.items():
        if any(indicator in response_headers for indicator in indicators):
            return True

    return False

def identify_firewall(response_headers):
    scores = {
        "Cloudflare": 0,
        "Akamai": 0,
        "Incapsula": 0,
        "Verizon Digital Media Services": 0
    }

    if "CF-RAY" in response_headers:
        scores["Cloudflare"] += 2
    if "CF-Request-ID" in response_headers:
        scores["Cloudflare"] += 2
    if "CF-IPCountry" in response_headers:
        scores["Cloudflare"] += 3
    if "CF-Cache-Status" in response_headers:
        scores["Cloudflare"] += 2
    if "CF-Edge-Workaround" in response_headers:
        scores["Cloudflare"] += 2
    if "CF-Powered-By" in response_headers:
        scores["Cloudflare"] += 2

    if "Akamai" in response_headers.get("Server", ""):
        scores["Akamai"] += 2
    if "Edge-Control" in response_headers:
        scores["Akamai"] += 2
    if "X-Akamai-Origin-Hop" in response_headers:
        scores["Akamai"] += 3
    if "X-Akamai-Request-ID" in response_headers:
        scores["Akamai"] += 2

    if "X-CDN" in response_headers and response_headers["X-CDN"] == "Incapsula":
        scores["Incapsula"] += 3
    if "X-Incapsula-Config-ID" in response_headers:
        scores["Incapsula"] += 2
    if "X-Incapsula-Response" in response_headers:
        scores["Incapsula"] += 2
    if "X-Incapsula-Request-ID" in response_headers:
        scores["Incapsula"] += 2

    if "X-EC-Debug" in response_headers:
        scores["Verizon Digital Media Services"] += 2
    if "X-EC-Error-Code" in response_headers:
        scores["Verizon Digital Media Services"] += 2
    if "X-EC-Error-Message" in response_headers:
        scores["Verizon Digital Media Services"] += 2
    if "X-EC-Request-ID" in response_headers:
        scores["Verizon Digital Media Services"] += 2
    if "Server" in response_headers and "Verizon Digital Media Services" in response_headers["Server"]:
        scores["Verizon Digital Media Services"] += 3

    if max(scores.values()) > 0:
        return max(scores, key=scores.get)
    else:
        return "Unknown"

def process_payloads(url, payloads_file, cookie, output_file, all_results, user_agents=None, verbose=False):
    results = []
    with open(payloads_file) as f:
        payloads = [line.strip() for line in f]
    for i, payload in enumerate(payloads, start=1):
        if user_agents is None:
            user_agent = None
        else:
            user_agent = random.choice(user_agents)
        success, url_with_payload, response_time, error_message, response_code, response_headers, response_body = perform_request(url, payload, cookie, user_agent, verbose)
        firewall_detected = is_firewall_detected(response_code, response_time, response_headers, response_body)

        if firewall_detected:
            firewall_name = identify_firewall(response_headers)
        else:
            firewall_name = "NO Firewall"

        result_line = f"{url_with_payload} - Response Time: {response_time:.2f} seconds - Status: {'Success' if success else 'Failed'} - Firewall: {firewall_name} - HTTP Status Code: {response_code}"
        if user_agent is not None:
            result_line += f" - User-Agent: {user_agent}"
        if response_time >= 10 or (all_results and success):
            results.append(result_line)
            print(f"\033[92m{result_line}\033[0m")
        else:
            print(f"\033[91m{result_line}\033[0m")
        if output_file:
            with open(output_file, "a") as f:
                f.write(result_line + "\n")
    return results

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", help="Single URL to scan.")
    parser.add_argument("-l", "--list", help="Text file containing a list of URLs to scan.")
    parser.add_argument("-p", "--payloads", required=True, help="Text file containing the payloads to append to the URLs.")
    parser.add_argument("-c", "--cookie", help="Cookie to include in the GET request.")
    parser.add_argument("-t", "--threads", typeint, help="Number of threads to use for scanning.")
parser.add_argument("-o", "--output", help="Text file to output the results to.")
parser.add_argument("-a", "--all", action="store_true", help="Output all results, not just successful ones.")
parser.add_argument("-v", "--verbose", action="store_true", help="Increase verbosity of output.")
parser.add_argument("-uas", "--user-agents", help="Text file containing a list of user agents to use for scanning.")

args = parser.parse_args()

if args.list:
    with open(args.list) as f:
        urls = [line.strip() for line in f]
else:
    urls = [args.url]

if args.user_agents:
    with open(args.user_agents) as f:
        user_agents = [line.strip() for line in f]
else:
    user_agents = None

for url in urls:
    process_payloads(url, args.payloads, args.cookie, args.output, args.all, user_agents, args.verbose)

if __name__ == "__main__":
    main()