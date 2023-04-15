# Auto generate code for ecli server api

## API definitions

HTTP request | Description
------------- | -------------
**GET** /list | Get list of running tasks
**POST** /start | Start a new task
**POST** /stop | Stop a task by id or name

Requests sent to:
+ `list` gets running programs.  
+ `start` with `program_data_buf`, program type, extra args and optional btf data.
+ `stop` with id or name, terminating coresponding program.

## Steps to generate code  

```shell
mkdir -p ~/bin/openapitools
curl https://raw.githubusercontent.com/OpenAPITools/openapi-generator/master/bin/utils/openapi-generator-cli.sh > ~/bin/openapitools/openapi-generator-cli
chmod u+x ~/bin/openapitools/openapi-generator-cli
cd ecli/api && ~/bin/openapitools/openapi-generator-cli generate -g rust-server -i apis.yaml
```


