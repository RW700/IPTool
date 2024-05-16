## IP Scanner Tool:

### Usage:

Tool has three methods of use: **search**, **status**, and **difference**

-   When the tool is run with the `--search` flag it runs an scan and returns all active IP's on the 192.168.1.0 suite.
-   When the tool is run with the `--status` flag, it must be followed with the IP addresses you want to scan and it will return if they are live (in green) or if not (in red), and the response time if active. IP's should be seperated by a space, or if there is a dash it will run on all the intermediate IPs. For instance `--status 192.168.1.1 192.168.1.19-24`
-   When the tool is run with the `--difference` flag, it will compare a json file of the last search with a new search and print out any newly found IPs in green and any that dissappeared in red
