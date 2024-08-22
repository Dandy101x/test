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

def perform_request(url, payload, cookie, user_agent, verbose, headers=None):
    url_with_payload = url.replace("*", payload)
    start_time = time.time()
    request_headers = {}
    if cookie:
        request_headers["Cookie"] = cookie
    if user_agent:
        request_headers["User-Agent"] = user_agent
    if headers:
        request_headers.update(headers)

    try:
        response = requests.get(url_with_payload, headers=request_headers)
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
        logger.debug(f"7) Headers: {request_headers}")
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

def parse_request_file(request_file, payload):
    with open(request_file, "r") as f:
        request_data = f.read()
    request_data = request_data.replace("{{payload}}", payload)
    lines = request_data.splitlines()
    url = lines[0].split(" ")[1]
    headers = {}
    for line in lines[1:]:
        if line.strip():
            key, value = line.split(": ", 1)
            headers[key] = value
    return url, headers

def process_payloads(url, payloads_file, cookie, output_file, all_results, user_agents=None, verbose=False, headers=None):
    results = []
    with open(payloads_file) as f:
        payloads = [line.strip() for line in f]
    for i, payload in enumerate(payloads, start=1):
        if user_agents is None:
            user_agent = None
        else:
            user_agent = random.choice(user_agents)
        request_file = "request.txt"  # assume the raw HTTP request file is named "request.txt"
        url, headers = parse_request_file(request_file, payload)
        success, url_with_payload, response_time, error_message, response_code, response_headers, response_body = perform_request(url, payload, cookie, user_agent, verbose, headers)
        firewall_detected = is_firewall_detected(response_code, response_time, response_headers, response_body)

        if firewall_detected:
            firewall_name = identify_firewall(response_headers)
        else:
            firewall_name = "NO Firewall"

        result_line = f"{i}) {url_with_payload} - Response Time: {response_time:.2f} seconds - Status: {'Success' if success else 'Failed'} - Firewall: {firewall_name} - HTTP Status Code: {response_code}"
        if user_agent is not None:
            result_line += f" - User-Agent: {user_agent}"
        if response_time >= 10 or (all_results and success):
            results.append(result_line)
            print(f"-----------------------------------------------------------------------------------------")
            print(f"\033[92m{result_line}\033[0m")
        else:
            print(f"-----------------------------------------------------------------------------------------")
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
    parser.add_argument("-t", "--threads", type=int, help="Number of concurrent threads (0-10).")
    parser.add_argument("-o", "--output", help="File to save all results.")
    parser.add_argument("--all-results", action="store_true", help="Save all results, not just vulnerabilities.")
    parser.add_argument("--UserAgent", nargs="?", const="UserAgent.txt", help="File containing a list of random user agents.")
    parser.add_argument("-v", "--VERBOSE", action="store_true", help="Enable verbose mode")
    parser.add_argument("-r", "--request", help="File containing a raw HTTP request (like Burp Suite)")
    args = parser.parse_args()

    if not args.url and not args.list and not args.request:
        parser.error("Either --url, --list, or --request must be specified.")

    if args.url:
        urls = [args.url]
    elif args.list:
        urls = [line.strip() for line in open(args.list)]
    else:
        url, headers = parse_request_file(args.request, "")
        with open(args.payloads) as f:
            payloads = [line.strip() for line in f]
        urls = [url.replace("*", payload) for payload in payloads]

    threads = []
    for url in urls:
        user_agents = None
        if args.UserAgent:
            user_agents_file = args.UserAgent
            if not os.path.exists(user_agents_file):
                user_agents_file = os.path.join(os.path.dirname(__file__), user_agents_file)
            with open(user_agents_file) as f:
                user_agents = [line.strip() for line in f]
        if args.threads == 0:
            if args.request:
                process_payloads(url, args.payloads, args.cookie, args.output, args.all_results, user_agents, verbose=args.VERBOSE, headers=headers)
            else:
                process_payloads(url, args.payloads, args.cookie, args.output, args.all_results, user_agents, verbose=args.VERBOSE)
        else:
            if args.request:
                t = threading.Thread(target=process_payloads, args=(url, args.payloads, args.cookie, args.output, args.all_results, user_agents, args.VERBOSE, headers))
            else:
                t = threading.Thread(target=process_payloads, args=(url, args.payloads, args.cookie, args.output, args.all_results, user_agents, args.VERBOSE))
            threads.append(t)
            t.start()

    if args.threads > 0:
        for t in threads:
            t.join()

if __name__ == "__main__":
    main()