import boto3
import json
import logging
import datetime
from elasticsearch import Elasticsearch, RequestsHttpConnection
import uuid
from requests_aws4auth import AWS4Auth
import requests

logger = logging.getLogger()
logger.setLevel('ERROR')

ELASTIC_HOST = 'https://vpc-photos-cr73giiqwxko7a2t22rzqu44rq.us-east-1.es.amazonaws.com'
ELASTIC_PORT = 9200
ELASTIC_REGION = 'us-east-1'
ELASTIC_SERVICE = 'es'

credentials = boto3.Session().get_credentials()

awsauth = AWS4Auth(credentials.access_key, credentials.secret_key, 'us-east-1', 'es', session_token=credentials.token)


class BaseObject(object):
    @classmethod
    def from_dict(cls, d):
        raise NotImplementedError('Not implement yet')

    @classmethod
    def from_json_str(cls, s):
        d = json.loads(s)
        return cls.from_dict(d)

    def to_dict(self):
        raise NotImplementedError('Not implement yet')

    def to_json_str(self):
        d = self.to_dict()
        return json.dumps(d)


class SearchResponse(BaseObject):
    def __init__(self, results):
        assert isinstance(results, list)
        for r in results:
            assert isinstance(r, Photo)
        self.results = results

    @classmethod
    def from_dict(cls, d):
        c = cls(results=[])
        for o in d['results']:
            c.add_result(Photo.from_dict(o))

    def add_result(self, photo):
        assert isinstance(photo, Photo)
        self.results.append(photo)

    def to_dict(self):
        return {'results': [o.to_dict() for o in self.results]}


class Photo(BaseObject):
    def __init__(self, url, labels):
        assert isinstance(url, str)
        assert isinstance(labels, list)
        for l in labels:
            assert isinstance(l, str)

        self.url = url
        self.labels = labels

    @classmethod
    def from_dict(cls, d):
        return cls(int(d['url']), d['labels'])

    def to_dict(self):
        return {
            'url': self.url,
            'labels': self.labels
        }


class Error(BaseObject):
    def __init__(self, code, message):
        assert isinstance(code, int)
        assert isinstance(message, str)
        self.code = code
        self.message = message

    @classmethod
    def from_dict(cls, d):
        return cls(int(d['code']), d['message'])

    def to_dict(self):
        return {
            'code': self.code,
            'message': self.message
        }


def build_s3_address(bucket, _id):
    # https://s3.amazonaws.com/cloudhw3bucket/201926383_22de827db0.jpg
    base = 'https://s3.amazonaws.com/'
    return base + bucket + '/' + _id


def build_response(status, body):
    return {
        'statusCode': status,
        'body': body
    }


def handler(event, context):
    logger.error('trigger lambda')

    try:
        lex_client = boto3.client('lex-runtime')

    except Exception:
        err = Error(-1, 'Something wrong with client.')
        return build_response('500', err.to_json_str())

    try:
        query = event['queryStringParameters']['q']
        query = query.replace('+', ' ')
    except KeyError as e:
        err = Error(-1, str(e))
        return build_response('500', err.to_json_str())

    logger.error('to lex')
    try:
        lex_output = lex_client.post_text(
            botName='getObjectBot',
            botAlias='getObject',
            userId=str(uuid.uuid4()),
            sessionAttributes={},
            requestAttributes={},
            inputText=query
        )
    except Exception as e:
        err = Error(-1, str(e))
        return build_response('500', err.to_json_str())

    try:
        slots = lex_output['slots']
        obj_a = slots['obj_a']
        obj_b = slots['obj_b']

    except KeyError as e:
        err = Error(-1, str(e))
        return build_response('500', err.to_json_str())

    logger.error(str(obj_a))
    logger.error(str(obj_b))

    # try:
    #     es_client = Elasticsearch(
    #         hosts=[{'host': ELASTIC_HOST}],
    #         # hosts=[{'host': ELASTIC_HOST, 'port': ELASTIC_PORT}],
    #         http_auth=awsauth,
    #         use_ssl=True,
    #         verify_certs=True,
    #         connection_class=RequestsHttpConnection
    #     )
    # except Exception as e:
    #     err = Error(-1, 'Something wrong with es client.')
    #     return err.to_json_str()

    labels = [obj_a, obj_b] if obj_b is not None else [obj_a]

    esq = {
        'size': 100,
        'query': {
            'bool': {
                "must": [
                    {"terms": {"labels": labels}}
                ]
            }
        }
    }
    logger.error('to es')

    index = 'photos'
    type = 'lambda-type'
    url1 = ELASTIC_HOST + '/' + index + '/_search'
    headers = {"Content-Type": "application/json"}

    res = requests.get(url1, auth=awsauth, headers=headers, data=json.dumps(esq))
    print(res.json())
    try:
        hits = res.json()['hits']['hits']
        logger.error(str(res.json()['hits']))
    except KeyError:
        hits = []

    # build response
    print(hits)
    rps = SearchResponse([])
    for h in hits:
        new_photo = Photo(build_s3_address(h['_source']['bucket'], h['_source']['objectKey']), h['_source']['labels'])
        rps.add_result(new_photo)
    logger.error(rps.to_json_str())
    
    return build_response('200', rps.to_json_str())