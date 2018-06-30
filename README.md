# Virtual host bruteforcer
Virtual host bruteforcer is a tool designed to help 

### Status: in development

### What is done:
 - bruteforce a single vhost against given network range
 - multithreading, ability to change the number of working threads
 - two modes: show all not empty responses or search for a given string in the response
 - two verbosity levels
 - ability to set custom protocol
 - ability to set custom connection timeout
 - colored output
 - ability to set custom uri
 - ip range input in different formats (single IP, CIDR, range)
 
 ### To do:
 - ~~scan against a single host~~
 - ~~bruteforce a list of vhosts (from dict) against one (or multiple) server ip~~
 - ~~ability to save all valid responses as html files to a given dir~~
 - ~~scan against a list of ip's from file~~
 - pritify the readme file, describe vhost bruteforce advantages
 - add usage documentation to readme
 - add zone to host from a dict (base word + different zones, like '.dev','.local')
 - ability to configure port?
 - ~~ability to show curl PoC command~~
 - ~~add some examples to the console help output~~
 - ~~prescan live hosts before vhost bruteforce (the idea is to find web servers before bruteforcing vhosts)~~
 - mode for both http & https protocol?
 - ~~filter bad vhosts for given host when the same response returned for each our request(or use another more complex filtering method? length delta?)~~
 - ~~refactor parameters (auto cast them)~~
 
 ### Why do we need vhost bruteforce? (draft):
 - dns records may not have records about some sweet subdomains
 - helps to bypass cloud protection solutions (like cloudflare) if we somehow can guess victim's real ip range, but don't know which particular server hosts the applications.