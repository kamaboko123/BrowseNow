#!/usr/bin/python

import ConfigParser

config = ConfigParser.ConfigParser()
config.read('./browsenow_config')

lambda_conf = {
        'filename' : 'lambda_func/bn_config',
        'src_section' : 'lambda',
        'dst_section' : 'lambda'
}

config_lambda = ConfigParser.ConfigParser()
config_lambda.add_section(lambda_conf['dst_section'])

for item in config.items(lambda_conf['src_section']):
    print item
    config_lambda.set(lambda_conf['dst_section'], item[0],  item[1])

with open(lambda_conf['filename'], 'w') as configfile:
    config_lambda.write(configfile)


