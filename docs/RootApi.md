# py_insightvm_sdk.RootApi

All URIs are relative to *https://ivmconsole*

Method | HTTP request | Description
------------- | ------------- | -------------
[**resources**](RootApi.md#resources) | **GET** /api/3 | Resources


# **resources**
> Links resources()

Resources

Returns a listing of the resources (endpoints) that are available to be invoked in this API.

### Example
```python
from __future__ import print_function
import time
import py_insightvm_sdk
from py_insightvm_sdk.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = py_insightvm_sdk.RootApi()

try:
    # Resources
    api_response = api_instance.resources()
    pprint(api_response)
except ApiException as e:
    print("Exception when calling RootApi->resources: %s\n" % e)
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**Links**](Links.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json;charset=UTF-8

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

