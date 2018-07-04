#!/usr/bin/python
# Author: Dzmitry Savitski
# Get a new version at: https://github.com/dzmitry-savitski/vhost_bruteforcer

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
prescan_results = {}
response_delta = 100
show_curl = False
resp_dir = ''


def main():
    args = parse_arguments()
    update_globals(args)
    set_logging_level(args.verbose)
    print_welcome_message()
    scan_args = pack_scan_arguments(args)
    start_scan(scan_args)


def update_globals(args):
    global ok_string, protocol, path, req_timeout, threads, response_delta, show_curl, resp_dir
    ok_string = args.ok_string
    protocol = args.protocol
    path = args.uri
    req_timeout = args.timeout
    threads = args.threads
    response_delta = response_delta
    show_curl = args.show_curl
    resp_dir = args.resp_dir


def configuration():
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    original_sigint_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGINT, original_sigint_handler)


def check_connection(ip):
    try:
        request_url = protocol + '://' + str(ip) + path
        request_headers = {'Host': 'neverexisting.domain'}
        response = requests.get(request_url, headers=request_headers, allow_redirects=False, verify=False,
                                timeout=req_timeout)
        return ip, True, len(response.text)
    except requests.exceptions.RequestException:
        return ip, False, 0
    except KeyboardInterrupt:
        pass


def prescan(ip_range):
    global prescan_results
    logging.warn(colored('Starting prescan for {} ip addresses'.format(len(ip_range)), 'green'))

    valid_ips = []
    try:
        pool = Pool(threads)
        for ip, status, response_length in pool.imap_unordered(check_connection, ip_range):
            if status:
                prescan_results[str(ip)] = response_length
                valid_ips.append(str(ip))
                logging.warn(colored('[prescan found] ip: {}'.format(ip), 'green'))
            else:
                logging.info(colored('[prescan failed] ip: {}'.format(ip), 'red'))
    except KeyboardInterrupt:
        print('Terminated by keyboard')
        exit(1)

    logging.warn(colored('Prescan finished, found {} valid servers'.format(len(valid_ips)), 'green'))
    return valid_ips


def pack_scan_arguments(args):
    ip_range = get_ips(args)
    if args.prescan:
        ip_range = prescan(ip_range)

    hosts = get_hosts(args)

    print_start_scan_message(hosts, ip_range, args)

    scan_args = []
    for ip in ip_range:
        for host in hosts:
            scan_args.append((ip, host))
    return scan_args


def start_scan(scan_args):
    thread_pool = Pool(threads)
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
        validate_response(host, str(ip), response)
    except requests.exceptions.RequestException:
        logging.info(colored('[connection failed] {}'.format(ip), 'red'))
    except KeyboardInterrupt:
        pass


def validate_response(host, ip, response):
    if ok_string:
        validate_ok_string(host, ip, response)
    elif prescan_results:
        validate_response_length_delta(host, ip, response)
    else:
        validate_not_empty_response(host, ip, response)


def validate_ok_string(host, ip, response):
    valid = ok_string in response.text
    if valid:
        logging.warn(colored('[ok string found] ip: {}, host: {}'.format(ip, host), 'green'))
        check_findings_options(host, ip, response)
    else:
        logging.info(colored('[ok string failed] ip: {}, host: {}'.format(ip, host), 'red'))


def validate_response_length_delta(host, ip, response):
    delta = abs(len(response.text) - prescan_results[ip])

    if delta >= response_delta:
        logging.warn(colored('[response delta {} found] ip: {}, host: {}'.format(delta, ip, host), 'green'))
        check_findings_options(host, ip, response)
    else:
        logging.info(colored('[response delta failed] ip: {}, host: {}'.format(ip, host), 'red'))


def validate_not_empty_response(host, ip, response):
    if response.text:
        logging.warn(
            colored('[response length {} found] ip: {}, host: {}'.format(len(response.text), ip, host),
                    'green'))
        check_findings_options(host, ip, response)
    else:
        logging.info(colored('[response length failed] ip: {}, host: {}'.format(ip, host), 'red'))


def check_findings_options(host, ip, response):
    if show_curl:
        log_curl_command(host, ip)
    if resp_dir:
        save_response_to_file(host, ip, response)


def save_response_to_file(host, ip, response):
    global resp_dir
    text_file = open("{}{}_{}.html".format(resp_dir, ip, host), "w")
    text_file.write(response.text.encode('utf-8'))
    text_file.close()


def log_curl_command(host, ip):
    global protocol, path
    logging.warn(colored('Command to repeat the previous request: '
                         'curl -k -H "Host: {}" "{}://{}{}"'.format(host, protocol, ip, path), 'green'))


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


def print_welcome_message():
    logging.warn(colored('########################################################', 'green'))
    logging.warn(colored('########### Vhost bruteforcer by D. Savitski ###########', 'green'))
    logging.warn(colored('########################################################', 'green'))


def print_start_scan_message(hosts, ip_range, args):
    logging.warn(colored('########################################################', 'green'))
    ip_count = len(ip_range)
    hosts_count = len(hosts)
    total_requests = ip_count * hosts_count
    logging.warn(colored(
        'Starting scan. Ip addresses: {}, hosts: {}, totlal requests to make: {}'.format(ip_count, hosts_count,
                                                                                         total_requests),
        'green'))
    if hosts_count > 2 and not args.prescan:
        logging.warn(colored(
            'Multiple vhosts for one ip detected. It\'s recommended to find live hosts first using --prescan option',
            'green'))
    logging.warn(colored('########################################################', 'green'))


def parse_arguments():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description='The script is designed to bruteforce host header for a given '
                                                 'network range or against a single host.',
                                     epilog='''
Usage examples:

./vh_bruteforcer.py -h www.victim.com -ip 10.10.10.0/24 -ok \'My_Site\'
Bruteforce \'www.victim.com\' vhost in the given subnet returning \'My_Site\' in the response

./vh_bruteforcer.py -h www.victim.com -ip 10.10.10.11-10.10.10.55 -v -t 10
Find all servers with not empty requests against given network range in verbose mode using 10 threads

./vh_bruteforcer.py --hosts ./hosts_list.txt -ip 10.10.10.0/24 --prescan -v
Bruteforce multiple vhosts against the subnet, use prescan mode to identify live hosts first and turn on response delta mode

./vh_bruteforcer.py -h www.victim.com -ips ./ip_list.txt --protocol http --save-resp-dir /tmp/scan/
Bruteforce one vhost in http mode, take ip ranges from file, save all valid responses to files in the given dir

./vh_bruteforcer.py -h www.victim.com -ip 10.10.10.0/24 --timeout 5 --show-curl
Increase default request timeout and show a curl command to repeat each found response 
                                            ''')

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
    parser.add_argument('--prescan', required=False, default=False, action='store_true', dest='prescan',
                        help='Find live hosts before vhost bruteforce. Saves time in case we have many vhosts to scan '
                             'against each ip address. Prescan is made with unexisting vhost and response length is '
                             'used to detect valid subdomains.')

    parser.add_argument('--resp-delta', required=False, default=100, dest='response_delta', type=int, metavar='100',
                        help='Option is a delta in characters to find a valid vhost while scanning one valid server. '
                             'Default is 100 characters.')
    parser.add_argument('-ok', '--ok-string', required=False, metavar='\'Victim_title\'', dest='ok_string',
                        help='This string should present in a valid response. By default - all not empty responses '
                             'are shown.')
    parser.add_argument('--uri', required=False, metavar='/', default="/", dest='uri',
                        help='Uri (path) to use in each request. By default - \'/\'')
    parser.add_argument('--timeout', required=False, metavar='0.5', default="1", dest='timeout', type=float,
                        help='Request timeout, by default - 1 sec.')
    parser.add_argument('--protocol', required=False, metavar='https', default="https", choices=['http', 'https'],
                        dest='protocol', help='Protocol to send requests by. By default https will be used.')
    parser.add_argument('-t', '--threads', required=False, metavar='5', default="1", type=int,
                        dest='threads', help='Number of threads. By default script works in single-thread mode.')
    parser.add_argument('-v', '--verbose', required=False, default=False, action='store_true', dest='verbose',
                        help='Show all failed attempts and debug information')
    parser.add_argument('--show-curl', required=False, default=False, action='store_true', dest='show_curl',
                        help='Show curl command to repeat valid responses')
    parser.add_argument('--save-resp-dir', required=False, metavar='/tmp/', dest='resp_dir',
                        help='Save all valid responses as html files to the given directory')
    return parser.parse_args()


if __name__ == "__main__":
    configuration()
    main()
