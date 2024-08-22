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
        response_body = response.text  # Add this line
    except requests.RequestException as e:
        return True, url_with_payload, time.time() - start_time, str(e), 0, {}, ""  # Return 7 values in except block

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
    # Check for common WAF headers
    waf_headers = ["X-CDN", "X-Cache", "X-WAF", "X-Web-Firewall", "X-Content-Type-Options"]
    if any(header in response_headers for header in waf_headers):
        return True

    # Check for HTTP response codes
    blocked_codes = [403, 429, 451]
    if response_code in blocked_codes:
        return True

    # Check for response time
    if response_time > 500:  # 500ms threshold
        return True

    # Check for response body
    blocked_keywords = ["blocked", "denied", "access denied"]
    if any(keyword in response_body.lower() for keyword in blocked_keywords):
        return True

    # Check for known WAF response codes and headers
    known_waf_indicators = {
        "Cloudflare": ["X-CDN", "X-Cache"],
        "Akamai": ["X-Akamai-Origin-Hop", "X-Akamai-Request-ID"],
        "Incapsula": ["X-CDN", "X-Incapsula-Response"],
        # Add more known WAF indicators here
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

    # Cloudflare
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

    # Akamai
    if "Akamai" in response_headers.get("Server", ""):
        scores["Akamai"] += 2
    if "Edge-Control" in response_headers:
        scores["Akamai"] += 2
    if "X-Akamai-Origin-Hop" in response_headers:
        scores["Akamai"] += 3
    if "X-Akamai-Request-ID" in response_headers:
        scores["Akamai"] += 2

    # Incapsula
    if "X-CDN" in response_headers and response_headers["X-CDN"] == "Incapsula":
        scores["Incapsula"] += 3
    if "X-Incapsula-Config-ID" in response_headers:
        scores["Incapsula"] += 2
    if "X-Incapsula-Response" in response_headers:
        scores["Incapsula"] += 2
    if "X-Incapsula-Request-ID" in response_headers:
        scores["Incapsula"] += 2

    # Verizon Digital Media Services
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

    # Return the WAF with the highest score
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
            firewall_name = identify_firewall(response_headers)  # Call identify_firewall to get the actual firewall name
        else:
            firewall_name = "NO Firewall"  # Explicitly set to "NO Firewall" if none is detected

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
    args = parser.parse_args()

    if not args.url and not args.list:
        parser.error("Either --url or --list must be specified.")

    if args.url:
        urls = [args.url]
    else:
        urls = [line.strip() for line in open(args.list)]

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
            process_payloads(url, args.payloads, args.cookie, args.output, args.all_results, user_agents, verbose=args.VERBOSE)
        else:
            t = threading.Thread(target=process_payloads, args=(url, args.payloads, args.cookie, args.output, args.all_results, user_agents, args.VERBOSE))
            threads.append(t)
            t.start()

    if args.threads > 0:
        for t in threads:
            t.join()

if __name__ == "__main__":
    main()