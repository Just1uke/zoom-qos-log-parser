```bash
usage: main.py [-h] [-o OUTPUT] [-d] [-q] [--parse-logs] [--dump-public-ips]
               [--dump-private-ips] [--dump-participants-by-public-ip]
               [--dump-participants-by-private-ip] [--dump-participants-list]
               [--dump-participants-list-with-ips] [--all-actions]
               input_files [input_files ...]

Parses Zoom QOS Logs into a usable format

positional arguments:
  input_files           QOS Logs provided by Zoom

optional arguments:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        Output directory
  -d, --debug           Print debug information
  -q, --quiet           Suppress all output
  --parse-logs          Parse logs and write them to the output directory
                        specified by -o.
  --dump-public-ips     Dumps the identified public IP addresses
  --dump-private-ips    Dumps the identified private IP addresses
  --dump-participants-by-public-ip
                        Dumps the identified participants by public IP address
  --dump-participants-by-private-ip
                        Dumps the identified participants by private IP
                        address
  --dump-participants-list
                        Dumps the identified participants
  --dump-participants-list-with-ips
                        Dumps the identified participants with the IP
                        addresses they used
  --all-actions         Runs all actions
```