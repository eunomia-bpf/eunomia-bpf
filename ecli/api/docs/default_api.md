# default_api

All URIs are relative to *http://localhost:8527*

Method | HTTP request | Description
------------- | ------------- | -------------
****](default_api.md#) | **GET** /list | Get list of running tasks
****](default_api.md#) | **POST** /log | get log
****](default_api.md#) | **POST** /start | Start a new task
****](default_api.md#) | **POST** /stop | Stop a task by id or name


# ****
> models::ListGet200Response ()
Get list of running tasks

### Required Parameters
This endpoint does not need any parameter.

### Return type

[**models::ListGet200Response**](_list_get_200_response.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# ****
> models::LogPost200Response (log_post_request)
get log

get log from server

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
  **log_post_request** | [**LogPostRequest**](LogPostRequest.md)|  | 

### Return type

[**models::LogPost200Response**](_log_post_200_response.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# ****
> models::ListGet200Response (optional)
Start a new task

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **optional** | **map[string]interface{}** | optional parameters | nil if no parameters

### Optional Parameters
Optional parameters are passed through a map[string]interface{}.

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **program_data_buf** | **swagger::ByteArray**|  | 
 **program_type** | **String**|  | 
 **program_name** | **String**|  | 
 **btf_data** | **swagger::ByteArray**|  | 
 **extra_params** | [**String**](String.md)|  | 

### Return type

[**models::ListGet200Response**](_list_get_200_response.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: multipart/form-data
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# ****
> models::StopPost200Response (list_get200_response_tasks_inner)
Stop a task by id or name

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
  **list_get200_response_tasks_inner** | [**ListGet200ResponseTasksInner**](ListGet200ResponseTasksInner.md)| Task id or name | 

### Return type

[**models::StopPost200Response**](_stop_post_200_response.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

