# log4j
Mirror of Apache log4j

## Changes from 1.2.17

 * Fixes for 
   * [CVE-2017-5645](https://nvd.nist.gov/vuln/detail/CVE-2017-5645). Remote code execution using the TCP socket server or UDP socket server
   * [CVE-2019-17571](https://nvd.nist.gov/vuln/detail/CVE-2019-17571). SocketServer class that is vulnerable to deserialization of untrusted data 
   * [CVE-2020-9488](https://nvd.nist.gov/vuln/detail/CVE-2020-9488). Improper validation of certificate with host mismatch in Apache Log4j SMTP appender.
   * [CVE-2021-4104](https://nvd.nist.gov/vuln/detail/CVE-2021-4104). Deserialization of untrusted data in JMSAppender.
 * Java 11 support
 * Compiled for java 8
