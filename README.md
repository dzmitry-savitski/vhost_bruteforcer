# Virtual host bruteforcer
Virtual host bruteforcer.

### Status: in development

### What is done:
 - bruteforce single vhost against given network range
 - multithreading, ability to change the number of working threads
 - two modes: show all not empty responses or search for given string in the response
 - two verbosity levels
 - ability to set custom protocol
 - ability to set custom connection timeout
 - colored output
 - ability to set custom uri
 - ip range input in different formats (CIDR, range)
 
 ### To do:
 - ~~scan against a single host~~
 - bruteforce a list of vhosts (from dict) against one server ip
 - ability to save all valid responses as html files to a given dir
 - scan against a list of ip's from file
 - pritify the readme file and add usage documentation
 - add zone to host from a dict (base word + different zones, like '.dev','.local')
 - ability to configure port?
 - ability to show curl PoC command
 - add some examples to the console help output