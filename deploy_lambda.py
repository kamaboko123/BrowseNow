#!/usr/bin/python

import os
import sys
import boto3
import subprocess
import ConfigParser

def get_path(relative_filename):
    if type(relative_filename) is not str:
        raise Excepiton("Error : invalid type value in args (get_path)")
    base = os.path.dirname(os.path.abspath(__file__))
    name = os.path.normpath(os.path.join(base, relative_filename))
    return name

def del_contents(paths):
    for target in paths:
        if os.path.exists(target):
            subprocess.check_call(["rm", "-rf", target])

def create_dirs(paths):
    for target in paths:
        subprocess.check_call(["mkdir", "-p", target])

def get_libs(requirements, target):
    cmd = "/bin/bash -c 'pip install -r %s -t %s > /dev/null 2>&1'" % (requirements, target)
    result = subprocess.check_call([cmd], shell=True)
    if result != 0:
        raise Exception("Error : get library codes")

def copy_dir_contents(src, dst):
    cmd = "/bin/bash -c 'cd %s; cp -r ./* %s'" % (src, dst)
    result = subprocess.check_call([cmd], shell=True)
    if result != 0:
        raise Exception("Error : copy dir contents")

def archive_dir_zip(src_dir, dst_file):
    cmd = "/bin/bash -c 'cd %s && zip -r %s .'" % (src_dir, dst_file)
    #cmd = "/bin/bash -c 'zip -r %s %s/*'" % (dst_file, src_dir)
    archive_result = subprocess.check_call([cmd], shell=True)
    if archive_result != 0:
        raise Exception("Error : Library code archive")

def upload_to_lambda(func_name, src_file):
    zipfile = open(src_file, 'rb')
    bin_zipfile = zipfile.read()

    client = boto3.client('lambda')
    ret = client.update_function_code(
        FunctionName=func_name,
        ZipFile=bin_zipfile
    )

def set_env_var(func_name, env_var):
    client = boto3.client('lambda')
    ret = client.update_function_configuration(
        FunctionName=func_name,
        Environment={"Variables":env_var}
    )


config = ConfigParser.ConfigParser()
config.read('./browsenow_config')

SRC_DIR = get_path("lambda_func")
REQUIREMENTS = get_path("lambda_func/requirements.txt")
TMP_DIR = get_path("tmp/lambda_tmp")
TMP_FILE = get_path("tmp/lambda.zip")

FUNC_NAME = config.get("deploy_lambda", "func_name")

ENV_VAR = {
    "AWS_KEY" : config.get("api_auth", "AWS_KEY"),
    "AWS_KEY_ID" : config.get("api_auth", "AWS_KEY_ID"),
    "TWITTER_CONSUMER_KEY" : config.get("api_auth", "TWITTER_CONSUMER_KEY"),
    "TWITTER_CONSUMER_SECRET": config.get("api_auth", "TWITTER_CONSUMER_SECRET")
}

sys.stdout.write("Clean up old contents : ")
del_contents([TMP_DIR, TMP_FILE])
create_dirs([TMP_DIR])
sys.stdout.write("OK\n")

sys.stdout.write("Get depend libraries : ")
get_libs(REQUIREMENTS, TMP_DIR)
sys.stdout.write("OK\n")

sys.stdout.write("Copy source codes : ")
copy_dir_contents(SRC_DIR, TMP_DIR)
sys.stdout.write("OK\n")

sys.stdout.write("archive codes : ")
archive_dir_zip(TMP_DIR, TMP_FILE)
sys.stdout.write("OK\n")

sys.stdout.write("Deploy to AWS Lambda : ")
upload_to_lambda(FUNC_NAME, TMP_FILE)
sys.stdout.write("OK\n")

sys.stdout.write("Set environment variable : ")
set_env_var(FUNC_NAME, ENV_VAR)
sys.stdout.write("OK\n")


