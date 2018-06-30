#!/usr/bin/python

from __future__ import print_function
import requests
import urllib3
import argparse
import netaddr
from termcolor import colored
from multiprocessing import Pool
import logging
import signal

# Default values
host = ''
ok_string = ''
protocol = 'http'
path = '/'
req_timeout = 1.0


def check_ip(ip):
    try:
        request_url = protocol + "://" + str(ip) + path
        request_headers = {"Host": host}
        response = requests.get(request_url, headers=request_headers, allow_redirects=False, verify=False,
                                timeout=req_timeout)
        validate_response(ip, response)
    except requests.exceptions.RequestException:
        logging.info(colored('[fail]', 'red') + str(ip))
    except KeyboardInterrupt:
        pass


def validate_response(ip, response):
    if ok_string:
        valid = ok_string in response.text
        if valid:
            logging.warn(colored('[found]', 'green') + str(ip))
        else:
            logging.info(colored('[fail]', 'red') + str(ip))
    else:
        response_length = len(response.text)
        if response_length > 0:
            logging.warn(colored('[found: ' + str(response_length) + ']', 'green') + str(ip))
        else:
            logging.info(colored('[fail]', 'red') + str(ip))


def parse_arguments():
    parser = argparse.ArgumentParser(description='The script can help to find server real ip adress. It sends '
                                                 'requests with given host header to each ip from given ip range and '
                                                 'tries to find a valid response.')
    parser.add_argument('--host', required=True, metavar='www.victim.com', dest='host',
                        help='Host to use. This argument will be sent in the host header with each request')
    parser.add_argument('-ip', '--ip-range', required=True, metavar='x.x.x.x/24', dest='ip_range',
                        help='The network range to scan. Available formats: CIDR notation (x.x.x.x/xx), simple range '
                             '(x.x.x.x - y.y.y.y).')
    parser.add_argument('-ok', '--ok-string', required=False, metavar='\'Victim_title\'', dest='ok_string',
                        help='This string should present in a valid response. By default - all not empty responses '
                             'are shown.')
    parser.add_argument('--uri', required=False, metavar='/', default="/", dest='uri',
                        help='Uri (path) to use in each request. By default - \'/\'')
    parser.add_argument('--timeout', required=False, metavar='0.5', default="1", dest='timeout',
                        help='Request timeout, by default - 1 sec.')
    parser.add_argument('--protocol', required=False, metavar='http', default="http", choices=['http', 'https'],
                        dest='protocol', help='Protocol to send requests by. By default http will be used.')
    parser.add_argument('-t', '--threads', required=False, metavar='5', default="1",
                        dest='threads', help='Number of threads. By default script works in single-thread mode.')
    parser.add_argument('-v', '--verbose', required=False, default=False, action='store_true', dest='verbose',
                        help='Show all failed attempts and debug information')
    return parser.parse_args()


def get_ip_range(ip_range_arg):
    if "/" in ip_range_arg:
        return list(netaddr.IPNetwork(ip_range_arg))
    else:
        ip_range_arg = ip_range_arg.replace(' ', '')
        ips = ip_range_arg.split('-')
        return list(netaddr.IPRange(ips[0], ips[1]))


def set_logging_level(verbose):
    if verbose:
        logging.basicConfig(level=logging.INFO, format='%(message)s')
    else:
        logging.basicConfig(level=logging.WARNING, format='%(message)s')


def update_globals():
    global host, ok_string, protocol, path, req_timeout
    host = args.host
    ok_string = args.ok_string
    protocol = args.protocol
    path = args.uri
    req_timeout = float(args.timeout)


if __name__ == "__main__":
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    args = parse_arguments()
    update_globals()
    set_logging_level(args.verbose)
    ip_range = get_ip_range(args.ip_range)

    # Start threads
    thread_pool = Pool(int(args.threads))

    original_sigint_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGINT, original_sigint_handler)

    try:
        records = thread_pool.map_async(check_ip, ip_range).get(9999999)
    except KeyboardInterrupt:
        print("Terminated by keyboard")
        thread_pool.terminate()
    else:
        thread_pool.close()
    thread_pool.join()
