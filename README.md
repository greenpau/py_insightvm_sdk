# py-insightvm-sdk

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

