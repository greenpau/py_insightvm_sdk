# py-insightvm-sdk

The automation of vulnerability management starts with using APIs to
gather and process information. This is an unofficial API client
library written in Python for Rapid7's InsightVM vulnerability
management platform.

## Getting Started

First, use the following command to install the library:

```bash
python setup.py install
```

Next, add `~/.py_insightvm_sdk.rc` for holding the credentials for InsightVM API:

```bash
$ cat ~/.py_insightvm_sdk.rc
[credentials]
username = "ivmapi"
password = "secret"

[manager]
host = "ivmconsole"
port = "443"
protocol = "https"
```

Finally, test the library by getting the list of asset groups:

```bash
ivm-client --get-asset-groups
```

The other available commands are:

```bash
ivm-client --get-asset-groups --debug
ivm-client --get-tags --debug
ivm-client --get-tags --format yaml
ivm-client --get-sites --format yaml --debug
ivm-client --get-assets --format yaml --debug -o /tmp/assets.yaml
ivm-client --asset-ref /tmp/assets.yaml --get-vulnerabilities --format yaml
ivm-client --get-asset --asset-ref /tmp/assets.yaml --filter "name:nysrv1" --format yaml --debug
```

## Asset Management

### Individual Assets

The `ivm-client` has the option to get asset by its ID. For example, the below
command fetches basic information about the asset with ID 444 and stores it
in `444.yaml` file.

```bash
ivm-client --get-asset-by-id 444 --format yaml -o 444.yaml
```

Next, a user may further interrogate the data by referencing that output file.

```bash
$ ivm-client --asset-file 444.yaml --asset-data-category vulnerabilities --debug | column -t -s";"

msft-cve-2019-0598                       Microsoft CVE-2019-0598: Jet Database Engine Remote Code Execution Vulnerability                      2019-02-12
msft-cve-2019-0599                       Microsoft CVE-2019-0599: Jet Database Engine Remote Code Execution Vulnerability                      2019-02-12
msft-cve-2019-0600                       Microsoft CVE-2019-0600: HID Information Disclosure Vulnerability                                     2019-02-12
msft-cve-2019-0601                       Microsoft CVE-2019-0601: HID Information Disclosure Vulnerability                                     2019-02-12
msft-cve-2019-0602                       Microsoft CVE-2019-0602: Windows GDI Information Disclosure Vulnerability                             2019-02-12
msft-cve-2019-0603                       Microsoft CVE-2019-0603: Windows Deployment Services TFTP Server Remote Code Execution Vulnerability  2019-03-12
msft-cve-2019-0606                       Microsoft CVE-2019-0606: Internet Explorer Memory Corruption Vulnerability                            2019-02-12

$ ivm-client --asset-file 444.yaml --asset-data-category services --debug | column -t -s";"

tcp  80     HTTP                     Microsoft-HTTPAPI
udp  123    NTP
tcp  135    DCE Endpoint Resolution
udp  137    CIFS Name Service
tcp  139    CIFS                     Windows Server 2012 R2 Standard 6.3
tcp  442    HTTPS                    Symantec Endpoint Protection Manager
tcp  443    HTTPS                    Microsoft-HTTPAPI
tcp  445    CIFS                     Windows Server 2012 R2 Standard 6.3
tcp  1433   TDS                      SQL Server 2012
udp  1434   Microsoft SQL Monitor    SQL Server 2012
tcp  3389   RDP

$ ivm-client --asset-file 444.yaml --asset-data-category software --debug | column -t -s";"

Microsoft               Microsoft .NET Framework 2.0 SP2                                            SP2
Microsoft               Microsoft .NET Framework 3.0 SP2                                            SP2
Microsoft               Microsoft .NET Framework 3.5 SP1                                            SP1
Microsoft               Microsoft .NET Framework 4.6.1
Microsoft               Microsoft .NET Framework 4.6.1 Client Profile
Microsoft               Microsoft Internet Explorer 11.0.9600.19204                                 11.0.9600.19204
Microsoft               Microsoft Internet Information Services 8.5                                 8.5
Microsoft               Microsoft MSXML 6.30.9600.19198                                             6.30.9600.19198
Microsoft               Microsoft MSXML 8.110.9600.19198                                            8.110.9600.19198
Microsoft               Microsoft Visual Studio 2010 SP1                                            SP1
```

### High Risk Assets

The following command produces a list of "Top 100" assets by "Risk Score":

```bash
$ ivm-client --asset-ref /tmp/assets.yaml --get-high-risk-asset-ids --limit 100 --format csv -o /tmp/high.risk.assets.yaml
```
