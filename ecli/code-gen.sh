rm -rf server-codegen
if [ ! -d server-codegen ]; then
    mkdir server-codegen
fi


java -jar openapi-generator-cli.jar generate -i apis.yaml -g rust-server --additional-properties=packageName=ecli-server-codegen --global-property=apiTests=false,modelTests=false,apiDocs=false,modelDocs=false -o server-codegen
