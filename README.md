# Virtual host bruteforcer
Virtual host bruteforcer is a tool designed to brute force given host header (or list of them) against a given network range or single ip.

## Why do we need vhost bruteforcer?
 - some sweet subdomains may not be resolved by dns queries at all
 - this tool helps to bypass cloud protection solutions (like cloudflare, waf-as-a-service, etc.) if we somehow can guess victim's real ip range, but don't know which particular server hosts the applications.   

## Features:
 - multithreading, ability to change the number of working threads
 - bruteforce a single vhost against a given network range
 - scan multiple vhosts against a single ip or network range
 - both vhosts and ip ranges can be read from file
 - 3 modes of verifying valid responses: show all not empty responses, search for a given string in the response, prescan mode (compare request length delta with 100% invalid vhost)
 - saves time in prescan mode by finding live web servers first
 - ip range input in different formats (single IP, CIDR, network range)
 - two verbosity levels (show all failed requests in verbose mode)
 - ability to choose between https or http protocols
 - colored output
 - ability to set custom connection timeout
 - ability to set custom uri for request
 - option to save all valid responses as html files in given dir
 - can optionally show curl command to repeat each valid request

## Installation:
`pip install -r requirements.txt`

## Usage:
```
vh_bruteforcer.py [-h] (--host www.victim.com | --hosts /hosts.txt)
                         (-ip x.x.x.x/24 | -ips /ip_list.txt) [--prescan]
                         [--resp-delta RESPONSE_DELTA] [-ok 'Victim_title']
                         [--uri /] [--timeout 0.5] [--protocol https] [-t 5]
                         [-v] [--show-curl] [--save-resp-dir /tmp/]

The script is designed to bruteforce host header for a given network range or against a single host.

optional arguments:
  -h, --help            show this help message and exit
  --host www.victim.com
                        Host to use. This argument will be sent in the host
                        header with each request
  --hosts /hosts.txt    A file with hosts list, ane host per line.
  -ip x.x.x.x/24, --ip-range x.x.x.x/24
                        The network range to scan. Available formats: single
                        ip (x.x.x.x), CIDR notation (x.x.x.x/xx), simple range
                        (x.x.x.x - y.y.y.y).
  -ips /ip_list.txt, --ip-list /ip_list.txt
                        A file with list of ip addresses to scan. One ip (or
                        CIDR subnet, or network range) per line.
  --prescan             Find live hosts before vhost bruteforce. Saves time in
                        case we have many vhosts to scan against each ip
                        address. Prescan is made with unexisting vhost and
                        response length is used to detect valid subdomains.
  --resp-delta 100      Option is a delta in characters to find a valid vhost
                        while scanning one valid server. Default is 100
                        characters.
  -ok 'Victim_title', --ok-string 'Victim_title'
                        This string should present in a valid response. By
                        default - all not empty responses are shown.
  --uri /               Uri (path) to use in each request. By default - '/'
  --timeout 0.5         Request timeout, by default - 1 sec.
  --protocol https      Protocol to send requests by. By default https will be
                        used.
  -t 5, --threads 5     Number of threads. By default script works in single-
                        thread mode.
  -v, --verbose         Show all failed attempts and debug information
  --show-curl           Show curl command to repeat valid responses
  --save-resp-dir /tmp/
                        Save all valid responses as html files to the given
                        directory
```
#### Usage examples:
1. Bruteforce 'www.victim.com' vhost in the given subnet returning 'My_Site' in the response

    `./vh_bruteforcer.py --host www.victim.com -ip 10.10.10.0/24 -ok 'My_Site'`

2. Find all servers with not empty requests against given network range in verbose mode using 10 threads
    
    `./vh_bruteforcer.py --host www.victim.com -ip 10.10.10.11-10.10.10.55 -v -t 10`

3. Bruteforce multiple vhosts against the subnet, use prescan mode to identify live hosts first and turn on response delta mode
    
    `./vh_bruteforcer.py --hosts ./hosts_list.txt -ip 10.10.10.0/24 --prescan -v`

4. Bruteforce one vhost in http mode, take ip ranges from file, save all valid responses to files in the given dir
    
    `./vh_bruteforcer.py --host www.victim.com -ips ./ip_list.txt --protocol http --save-resp-dir /tmp/scan/`

5. Increase default request timeout and show a curl command to repeat each found response
    
    `./vh_bruteforcer.py --host www.victim.com -ip 10.10.10.0/24 --timeout 5 --show-curl`

 ### To do plans:
 - include headers into ok_string scan (optionally)?
 - fixing bugs
 - add mode to get subdomains and zones from a dict (base word + different zones, like '.dev','.local')
 - ability to configure port?
 - mode to scan both http & https protocols at once?
