#!/usr/bin/python

import ConfigParser
import traceback
import datetime
import tweepy
import oauth2
import boto3
import uuid
import time
import json
import re
import os
from urlparse import parse_qsl

config = ConfigParser.ConfigParser()
config.read('./bn_config')

CONSUMER_KEY = os.environ['TWITTER_CONSUMER_KEY']
CONSUMER_SECRET = os.environ['TWITTER_CONSUMER_SECRET']

CALLBACK_URL = config.get('lambda', 'tw_callback_url')

TW_REQUEST_TOKEN_URL = config.get('lambda', 'tw_request_token_url')
TW_AUTHENTICATE_URL = config.get('lambda', 'tw_authenticate_url')
TW_ACCESS_TOKEN_URL = config.get('lambda', 'tw_access_token_url')

MAIN_PAGE = config.get('lambda', 'page_main')
AUTH_ERROR_PAGE = config.get('lambda', 'page_auth_error')

DB_REGION = config.get('lambda', 'db_region')
DB_SESSION_TABLE = config.get('lambda', 'db_session_table')

AWS_ACCESS_KEY_ID = os.environ['AWS_KEY_ID']
AWS_ACCESS_KEY = os.environ['AWS_KEY']

APP_SESSION_EXPIRE_MIN = int(config.get('lambda', 'db_session_expire_min'))

def get_request_token():
    request_url = '%s?oauth_callback=%s' % (TW_REQUEST_TOKEN_URL, CALLBACK_URL)
    
    consumer = oauth2.Consumer(key=CONSUMER_KEY, secret=CONSUMER_SECRET)
    client = oauth2.Client(consumer)
    
    response, content = client.request(request_url)
    content_dic = dict(parse_qsl(content))
    
    return(content_dic['oauth_token'])

def auth_request():
    ret = {}
    try:
        request_token = get_request_token()
        ret['auth_url'] = '%s?oauth_token=%s' % (TW_AUTHENTICATE_URL, request_token)
        ret['success'] = True
    except:
        ret['success'] = False
    
    return(ret)

#def parse_querystr(string):
#    ret = {}
#    re_param = re.compile("(.*)=(.*)")
#    
#    tmp = map(lambda item: re_param.findall(item), map(lambda item: item.strip("&"), string.split('&')))
#    for item in tmp:
#        ret[item[0][0]] = item[0][1]
#    
#    return(ret)

def get_cookie_expires():
    expires=datetime.datetime.now()+datetime.timedelta(days=6)
    return(expires.strftime("%a, %d-%b-%Y %H:%M:%S GMT"))

def get_access_token(oauth_token, oauth_verifier):
    consumer = oauth2.Consumer(key=CONSUMER_KEY, secret=CONSUMER_SECRET)
    token = oauth2.Token(oauth_token, oauth_verifier)
    
    client = oauth2.Client(consumer, token)
    resp, content = client.request(TW_ACCESS_TOKEN_URL, "POST", body="oauth_verifier={0}".format(oauth_verifier))
    
    return(content)

def auth_access_token(oauth_token, oauth_verifier):
    resp = get_access_token(oauth_token, oauth_verifier)
    customer = dict(parse_qsl(resp))
    
    print customer
    
    if len(customer["screen_name"]) == 0:
        raise Error("Faild to confirm authentication")
    
    sid = str(uuid.uuid4())
    update_auth_session(sid, customer["user_id"], customer["oauth_token"], customer["oauth_token_secret"])
    
    #ret["success"] = True
    #ret["customer"] = customer

    ret = {"Location": "%s?auth=%d" % (MAIN_PAGE, 1), "Set-Cookie": ("SID=%s;expires=%s;" % (sid, get_cookie_expires()))}
    return(ret)

def update_auth_session(session_id, user_id, access_token, access_token_secret):
    
    db = get_db_session()
    
    expires_at = long(time.time()) + (APP_SESSION_EXPIRE_MIN * 60)
    
    resp = db.put_item(
        TableName=DB_SESSION_TABLE,
        Item={
            'id' : {'S': str(session_id)},
            'expires_at' : {'N' : str(expires_at)},
            'user_data' : {
                'M' : {
                    'user_id' : {'N' : str(user_id)},
                    'auth' : {
                        'M' : {
                            'access_token' : {'S' : str(access_token)},
                            'access_token_secret' : {'S' : str(access_token_secret)}
                        }
                    }
                }
            }
        }
    )
    
    return resp

def get_db_session():
    sess = boto3.Session(
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_ACCESS_KEY,
        region_name=DB_REGION
    )
    
    db = sess.client('dynamodb')
    
    return(db)

def get_credential(sid):
    db = get_db_session()
    cred = db.get_item(
        TableName=DB_SESSION_TABLE,
        Key={'id':{'S' : sid}}
    )
    if 'Item' not in cred.keys():
        return(None)
    
    return(cred['Item'])

def del_auth_session(session_id):
    db = get_db_session()
    resp = db.delete_item(
        TableName=DB_SESSION_TABLE,
        Key={
            'id' : {'S': str(session_id)}
        }
    )
    
    return resp
    

def get_twitter_api(access_key, access_key_secret):
    twauth = tweepy.OAuthHandler(CONSUMER_KEY, CONSUMER_SECRET)
    twauth.set_access_token(access_key, access_key_secret)
    api = tweepy.API(twauth)
    return(api)

def parse_db_credential_data(credential):
    ret = {}
    ret['user_id'] = credential['user_data']['M']['user_id']['N']
    ret['access_key'] = credential['user_data']['M']['auth']['M']['access_token']['S']
    ret['access_key_secret'] = credential['user_data']['M']['auth']['M']['access_token_secret']['S']
    
    return(ret)

def post_tweet(access_key, access_key_secret, tweet):
    twitter = get_twitter_api(access_key, access_key_secret)
    twitter.update_status(tweet)
    

#def post_tweet(sid, tweet):
#    credential = get_credential(sid)
#    print(credential['user_data'])
#    
#    twitter = get_twitter_api(credential['user_data']['M']['auth']['M']['access_token']['S'], credential['user_data']['M']['auth']['M']['access_token_secret']['S'])
#    twitter.update_status(tweet)

def check_credential(sid):
    credential = get_credential(sid)
    if credential is  None:
        return(False)
    twitter = get_twitter_api(credential['user_data']['M']['auth']['M']['access_token']['S'], credential['user_data']['M']['auth']['M']['access_token_secret']['S'])
    #print "[cred]"
    #print(credential['user_data'])
    if twitter.verify_credentials() != False:
        return(True)
    return(False)

def renew_sid(sid):
    credential = get_credential(sid)
    if credential is  None:
        raise Exception("failed to renew sid(old id is not found)")
    del_auth_session(sid)
    
    new_sid = str(uuid.uuid4())
    update_auth_session(new_sid, credential['user_data']['M']['user_id']['N'], credential['user_data']['M']['auth']['M']['access_token']['S'], credential['user_data']['M']['auth']['M']['access_token_secret']['S'])
    
    return new_sid


def lambda_handler(event, context):
    ret = {}
    
    print event
    
    if event['request-type'] == 'auth-request':
        ret = auth_request()
        return ret
    
    elif event['request-type'] == 'auth-callback':
        try:
            ret = auth_access_token(event['oauth_token'], event['oauth_verifier'])
            ret['success'] = True
        
        except Exception as e:
            print traceback.format_exc()
            ret['Location'] = AUTH_ERROR_PAGE
            ret['success'] = False
            ret['message'] = 'Failed to authorize'
        
        return ret
    
    elif event['request-type'] == 'post-tweet':
        print dict(parse_qsl(event['cookie'].replace(';', '&')))
        cookie = dict(parse_qsl(event['cookie'].replace(';', '&')))
        sid = cookie['SID']
        
        credential = parse_db_credential_data(get_credential(sid))
        
        ret = {}
        try:
            new_sid = renew_sid(sid)
            ret['Set-Cookie'] = ("SID=%s;expires=%s;" % (new_sid, get_cookie_expires()))
        
        except Exception:
            ret['success'] = False
            ret['Set-Cookie'] = ("SID=;")
            ret['detail'] = "auth error"
            return ret
        
        try:
            post_tweet(credential['access_key'], credential['access_key_secret'], event['body']['message'])
            ret['success'] = True
        except tweepy.error.TweepError as err:
            print err
            ret['success'] = False
            ret['detail'] = err.message[0]['message']
        except Exception as err:
            print err
            ret['success'] = False
            ret['detail'] = "Unknown error"
        
        return ret
    
    elif event['request-type'] == 'check-credential':
        cookie = dict(parse_qsl(event['cookie'].replace(';', '&')))
        sid = cookie['SID']
        
        ret['success'] = True
        ret['verify'] = check_credential(sid)
        
        return ret
    
    elif event['request-type'] == 'sid-regenerate-test':
        cookie = dict(parse_qsl(event['cookie'].replace(';', '&')))
        sid = cookie['SID']
        
        try:
            new_sid = renew_sid(sid)
            ret['Set-Cookie'] = ("SID=%s;expires=%s;" % (new_sid, get_cookie_expires()))
            ret['success'] = True
        except:
            ret['Set-Cookie'] = ("SID=;")
            ret['success'] = False
            ret['detail'] = "failed to renew sid"
        
        return ret
    
    else:
        ret['success'] = False
        return(json.dumps(ret))

if __name__ == '__main__':
    req = {}
    req["request-type"] = "auth-request"
    
    response = lambda_handler(req, None)
    print type(response)
    print response
