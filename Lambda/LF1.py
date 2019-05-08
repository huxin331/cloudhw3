import boto3
import json
import requests
from requests_aws4auth import AWS4Auth
import logging


logger = logging.getLogger()
logger.setLevel('ERROR')

region = 'us-east-1'  # e.g. us-west-1
service = 'es'
credentials = boto3.Session().get_credentials()
awsauth = AWS4Auth(credentials.access_key, credentials.secret_key, region, service, session_token=credentials.token)

host = 'https://vpc-photos-cr73giiqwxko7a2t22rzqu44rq.us-east-1.es.amazonaws.com'  # the Amazon ES domain, including https://
index = 'photos'
type = 'lambda-type'
url = host + '/' + index + '/' + type
url_delete = host + '/' + index 
# rekognition
client = boto3.client('rekognition')

headers = {"Content-Type": "application/json"}

s3 = boto3.client('s3')


def handler(event, context):
    print("trigger")
    for record in event['Records']:
        # Get the bucket name and key for the new file
        bucket = record['s3']['bucket']['name']
        key = record['s3']['object']['key']
        timestamp = record['eventTime']
    print(key)
    
    logger.error('[NEW OBJECT] ' + key)
    
    labels = [ ]
    response = client.detect_labels(Image={'S3Object': {'Bucket': bucket, 'Name': key}}, MaxLabels=10)
    
    for label in response['Labels']:
        print (label['Name'] + ' : ' + str(label['Confidence']))
        labels.append(label['Name'])
    logger.error('[NEW key] ' + str(labels))
    
    document = {"objectKey": key, "bucket": bucket, "createdTimestamp": timestamp, "labels": labels};
    r = requests.post(url, auth=awsauth, json=document, headers=headers)
    
    #deleteResponse = requests.delete(url_delete,auth=awsauth)
    
    print("done")
