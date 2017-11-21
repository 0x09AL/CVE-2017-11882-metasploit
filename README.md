# CVE-2017-11882-metasploit
This is a Metasploit module which exploits CVE-2017-11882 using the POC below:

https://embedi.com/blog/skeleton-closet-ms-office-vulnerability-you-didnt-know-about.


## Installation
1) Copy the cve_2017_11882.rb to /usr/share/metasploit-framework/modules/exploits/windows/local/
2) Copy the cve-2017-11882.rtf to /usr/share/metasploit-framework/data/exploits/

This module is a quick port to Metasploit and uses mshta.exe to execute the payload.

There are better ways to implement this module and exploit but will update it as soon as I have the time.
