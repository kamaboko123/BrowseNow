#!/usr/bin/python

import boto3
import ConfigParser

config = ConfigParser.ConfigParser()
config.read('../browsenow_config')

api_id = config.get("api_gateway", "api_gateway_id")

client = boto3.client('apigateway')
resp = client.get_export(
    restApiId=api_id,
    stageName='prod',
    exportType='swagger'
)

print resp['body'].read()
