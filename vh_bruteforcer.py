#!/usr/bin/python
# Author: Dzmitry Savitski
# Get new version at: https://github.com/dzmitry-savitski/vhost_bruteforcer

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
ok_string = ''
protocol = 'https'
path = '/'
req_timeout = 1.0
threads = 1


def main():
    args = parse_arguments()
    update_globals(args)
    set_logging_level(args.verbose)
    scan_args = pack_scan_arguments(args)

    start_scan(scan_args)


def update_globals(args):
    global ok_string, protocol, path, req_timeout, threads
    ok_string = args.ok_string
    protocol = args.protocol
    path = args.uri
    req_timeout = float(args.timeout)
    threads = int(args.threads)


def configuration():
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def pack_scan_arguments(args):
    ip_range = get_ips(args)
    hosts = get_hosts(args)
    print_welcome_message(hosts, ip_range)

    scan_args = []
    for ip in ip_range:
        for host in hosts:
            scan_args.append((ip, host))
    return scan_args


def start_scan(scan_args):
    thread_pool = Pool(threads)
    original_sigint_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGINT, original_sigint_handler)
    try:
        thread_pool.map_async(check_ip, scan_args).get(9999999)
    except KeyboardInterrupt:
        print('Terminated by keyboard')
        thread_pool.terminate()
    else:
        thread_pool.close()
    thread_pool.join()


def check_ip(args):
    (ip, host) = args
    try:
        request_url = protocol + '://' + str(ip) + path
        request_headers = {'Host': host}
        response = requests.get(request_url, headers=request_headers, allow_redirects=False, verify=False,
                                timeout=req_timeout)
        validate_response(response, host, str(ip))
    except requests.exceptions.RequestException:
        logging.info(colored('[connection failed] {}'.format(ip), 'red'))
    except KeyboardInterrupt:
        pass


def validate_response(response, host, ip):
    if ok_string:
        validate_ok_string(host, ip, response)
    else:
        validate_not_empty_response(host, ip, response)


def validate_ok_string(host, ip, response):
    valid = ok_string in response.text
    if valid:
        logging.warn(colored('[ok string found] ip: {}, host: {}'.format(ip, host), 'green'))
    else:
        logging.info(colored('[ok string failed] ip: {}, host: {}'.format(ip, host), 'red'))


def validate_not_empty_response(host, ip, response):
    if response.text:
        logging.warn(
            colored('[found response length ' + str(len(response.text)) + '] ip: {}, host: {}'.format(ip, host),
                    'green'))
    else:
        logging.info(colored('[response length failed] ip: {}, host: {}'.format(ip, host), 'red'))


def get_ips(args):
    if args.ip_list:
        ip_records = args.ip_list.read().splitlines()
        ip_records = filter(lambda item: item.strip(), ip_records)
        all_ips = []
        for record in ip_records:
            all_ips += get_ip_range(record)
        return all_ips
    else:
        return get_ip_range(args.ip_range)


def get_ip_range(ip_range_arg):
    if '/' in ip_range_arg:
        return list(netaddr.IPNetwork(ip_range_arg))
    elif '-' in ip_range_arg:
        ip_range_arg = ip_range_arg.replace(' ', '')
        ips = ip_range_arg.split('-')
        return netaddr.IPRange(ips[0], ips[1])
    else:
        return [netaddr.IPAddress(ip_range_arg)]


def get_hosts(args):
    if args.host:
        return [args.host]
    else:
        hosts_records = args.hosts.read().splitlines()
        return filter(lambda item: item.strip(), hosts_records)


def set_logging_level(verbose):
    if verbose:
        logging.basicConfig(level=logging.INFO, format='%(message)s')
    else:
        logging.basicConfig(level=logging.WARNING, format='%(message)s')


def print_welcome_message(hosts, ip_range):
    logging.warn(colored('########################################################', 'green'))
    logging.warn(colored('########### Vhost bruteforcer by D. Savitski ###########', 'green'))
    logging.warn(colored('########################################################', 'green'))
    ip_count = len(ip_range)
    hosts_count = len(hosts)
    total_requests = ip_count * hosts_count
    logging.warn(colored(
        'Starting scan. Ip addresses: {}, hosts: {}, totlal requests to make: {}'.format(ip_count, hosts_count,
                                                                                         total_requests),
        'green'))


def parse_arguments():
    parser = argparse.ArgumentParser(description='The script can help to find server real ip address. It sends '
                                                 'requests with given host header to each ip from given ip range and '
                                                 'tries to find a valid response.')

    group_host = parser.add_mutually_exclusive_group(required=True)
    group_host.add_argument('--host', metavar='www.victim.com', dest='host',
                            help='Host to use. This argument will be sent in the host header with each request')
    group_host.add_argument('--hosts', metavar='/hosts.txt', dest='hosts', type=argparse.FileType('r'),
                            help='A file with hosts list, ane host per line.')

    group_ip = parser.add_mutually_exclusive_group(required=True)
    group_ip.add_argument('-ip', '--ip-range', metavar='x.x.x.x/24', dest='ip_range',
                          help='The network range to scan. Available formats: single ip (x.x.x.x), CIDR notation ('
                               'x.x.x.x/xx), simple range (x.x.x.x - y.y.y.y).')
    group_ip.add_argument('-ips', '--ip-list', metavar='/ip_list.txt', dest='ip_list', type=argparse.FileType('r'),
                          help='A file with list of ip addresses to scan. One ip (or CIDR subnet, or network range) '
                               'per line.')

    parser.add_argument('-ok', '--ok-string', required=False, metavar='\'Victim_title\'', dest='ok_string',
                        help='This string should present in a valid response. By default - all not empty responses '
                             'are shown.')
    parser.add_argument('--uri', required=False, metavar='/', default="/", dest='uri',
                        help='Uri (path) to use in each request. By default - \'/\'')
    parser.add_argument('--timeout', required=False, metavar='0.5', default="1", dest='timeout',
                        help='Request timeout, by default - 1 sec.')
    parser.add_argument('--protocol', required=False, metavar='https', default="https", choices=['http', 'https'],
                        dest='protocol', help='Protocol to send requests by. By default http will be used.')
    parser.add_argument('-t', '--threads', required=False, metavar='5', default="1",
                        dest='threads', help='Number of threads. By default script works in single-thread mode.')
    parser.add_argument('-v', '--verbose', required=False, default=False, action='store_true', dest='verbose',
                        help='Show all failed attempts and debug information')
    return parser.parse_args()


if __name__ == "__main__":
    configuration()
    main()
