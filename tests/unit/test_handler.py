import json
import pytest
from src import app
import urllib.parse
import base64


def apigw_slack_base_event():
    """ Generates a fake slack challenge event.

    This is the base event and has no body. So you should add
    to whatever you need based on what you need the anything else to be.
    """

    return {'resource': '/slack',
            'path': '/slack',
            'httpMethod': 'POST',
            'headers': {
                'Accept': '*/*',
                'Accept-Encoding': 'gzip,deflate',
                'Content-Type': 'application/json',
                'Host': '<OBSFUCATED>',
                'User-Agent': 'Slackbot 1.0 (+https://api.slack.com/robots)',
                'X-Forwarded-For': '34.226.200.251', 'X-Forwarded-Port': '443',
                'X-Forwarded-Proto': 'https',
                'X-Slack-Request-Timestamp': '<OBSFUCATED>',
                'X-Slack-Signature': '<OBSFUCATED>'
            },
            'multiValueHeaders': {
                'Accept': ['*/*'],
                'Accept-Encoding': ['gzip,deflate'],
                'Content-Type': ['application/json'],
                'Host': ['<OBSFUCATED>'],
                'User-Agent': ['Slackbot 1.0 (+ht tps://api.slack.com/robots)'],
                'X-Amzn-Trace-Id': ['<OBSFUCATED>'],
                'X-Forwarded-For': ['<OBSFUCATED>'],
                'X-Forwarded-Port': ['443'], 'X-Forwarded-Proto': ['https'],
                'X-Slack-Request-Timestamp': ['<OBSFUCATED>'],
                'X-Slack-Signature': ['<OBSFUCATED>']
            },
            'queryStringParameters': None,
            'multiValueQueryStringParameters': None,
            'pathParameters': None,
            'stageVariables': {'Stage': '<OBSFUCATED>',
                               'ApiLambdaFunction': '<OBSFUCATED>'},
            'requestContext': {'resourceId': 'o17wi2', 'resourcePath': '/slack', 'httpMethod': 'POST',
                               'extendedRequestId': 'N5lBUHOoywMFXFg=', 'requestTime': '<OBSFUCATED>',
                               'path': '<OBSFUCATED>', 'accountId': '<OBSFUCATED>', 'protocol': 'HTTP/1.1',
                               'stage': '<OBSFUCATED>', 'requestTimeEpoch': 1538084565280,
                               'requestId': '<OBSFUCATED>',
                               'identity': {'cognitoIdentityPoolId': None, 'accountId': None, 'cognitoIdentityId': None,
                                            'caller': None, 'sourceIp': '<OBSFUCATED>', 'accessKey': None,
                                            'cognitoAuthenticationType': None, 'cognitoAuthenticationProvider': None,
                                            'userArn': None,
                                            'userAgent': 'Slackbot 1.0 (+https://api.slack.com/robots)', 'user': None},
                               'apiId': '<OBSFUCATED>'},
            'isBase64Encoded': False}





@pytest.fixture()
def apigw_slack_challenge_event():
    """Fakes a basic slack challenge event.
    """
    slack_challenge_event = apigw_slack_base_event()
    slack_challenge_event["body"] = '{"token":"<OBSFUCATED>","challenge":"somerandomdigits","type":"url_verification"}'
    return slack_challenge_event


@pytest.fixture()
def slack_unknown_content():
    """Fakes a call with unknown content type.
    """
    slack_unknown_content = apigw_slack_base_event()
    del slack_unknown_content['headers']['Content-Type']
    return slack_unknown_content


@pytest.fixture()
def slack_url_encoded():
    """Fakes a call with unknown content type.
    """
    slack_url_encoded = apigw_slack_base_event()
    slack_url_encoded['headers']['Content-Type'] = 'application/x-www-form-urlencoded'
    slack_url_encoded['body'] = "token=abIXST3MY2dOo9KyqrPyY0l9&team_domain=compeat&channel_name=directmessage&user_id=UPG49L0TH&command=%2Fit-list-test&text=&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT04HY6K21%2F1163195318885%2FVp4f4yPdOGF1dXe96A9E2i5U"
    return slack_url_encoded



@pytest.fixture()
def slack_json_as_json():
    """Fakes a call with unknown content type.
    """
    slack_json_as_json = apigw_slack_base_event()
    slack_json_as_json['body'] = ""
    return slack_json_as_json


@pytest.fixture()
def slack_json_as_string():
    """Fakes a call with unknown content type.
    """
    slack_json_as_string = apigw_slack_base_event()
    slack_json_as_string['body'] = ""
    return slack_json_as_string



def test_lambda_challenge(apigw_slack_challenge_event):
    
    # test challenge
    ret = app.lambda_handler(apigw_slack_challenge_event, "")
    assert ret['statusCode'] == 200

    data = json.loads(ret['body'])
    assert data == {"challenge": "somerandomdigits"}


def test_unknown_content_type(slack_unknown_content):

    # test unknown content
    ret = app.lambda_handler(slack_unknown_content, "")
    assert ret['statusCode'] == 415

    data = json.loads(ret['body'])
    assert data == {"Error": "Unexpected Content-Type (null)"}


def decode_b64_json(ret_body):
    """ utility to take ret['body']={'req_body_base64' : 'some64string=='}
        and return dictionary """

    b64_body = (json.loads(ret_body or {}))['req_body_base64']
    b64_bytes = b64_body.encode('utf-8')
    msg_bytes = base64.b64decode(b64_bytes)
    body_dict = json.loads(msg_bytes.decode('utf-8'))

    return body_dict


def test_url_encoded_content(slack_url_encoded):

    # test payload
    slack_url_encoded['headers']['X-Unit-Test'] = 'b64stub'
    ret = app.lambda_handler(slack_url_encoded, "")
    assert ret['statusCode'] == 200

    body_dict = decode_b64_json(ret['body'])

    assert body_dict == {
        'channel_name': ['directmessage'],
        'command': ['/it-list-test'],
        'response_url': ['https://hooks.slack.com/commands/T04HY6K21/1163195318885/Vp4f4yPdOGF1dXe96A9E2i5U'],
        'slack_event_type': 'slash-command',
        'team_domain': ['compeat'],
        'token': ['abIXST3MY2dOo9KyqrPyY0l9'],
        'user_id': ['UPG49L0TH']
    }


def test_url_encoded_content_passthru(slack_url_encoded):

    # ensure no errors
    slack_url_encoded['headers']['X-Unit-Test'] = 'passthru'

    ret = app.lambda_handler(slack_url_encoded, "")
    assert ret['statusCode'] == 200

    data = json.loads(ret['body'])
    assert data == {}


def test_payload_content_create_ticket(slack_url_encoded):

    CREATE_TICKET_PAYLOAD = "payload=%7B%22type%22%3A%22message_action%22%2C%22token%22%3A%22abIXST3MY2dOo9KyqrPyY0l9%22%2C%22action_ts%22%3A%221591302360.305165%22%2C%22team%22%3A%7B%22id%22%3A%22T04HY6K21%22%2C%22domain%22%3A%22compeat%22%7D%2C%22user%22%3A%7B%22id%22%3A%22UPG49L0TH%22%2C%22name%22%3A%22douglas.norment%22%2C%22username%22%3A%22douglas.norment%22%2C%22team_id%22%3A%22T04HY6K21%22%7D%2C%22channel%22%3A%7B%22id%22%3A%22D014R1SRSSZ%22%2C%22name%22%3A%22directmessage%22%7D%2C%22callback_id%22%3A%22create-ticket-from-slack-msg%22%2C%22trigger_id%22%3A%221178280893905.4610223069.9aafb644573a581f3251c8f1cff8008d%22%2C%22message_ts%22%3A%221591301772.000200%22%2C%22message%22%3A%7B%22client_msg_id%22%3A%22b56103b9-ab45-4e89-a1bf-fac88a76ad90%22%2C%22type%22%3A%22message%22%2C%22text%22%3A%22Some+message...%22%2C%22user%22%3A%22UPG49L0TH%22%2C%22ts%22%3A%221591301772.000200%22%2C%22team%22%3A%22T04HY6K21%22%2C%22blocks%22%3A%5B%7B%22type%22%3A%22rich_text%22%2C%22block_id%22%3A%22l%5C%2F6sd%22%2C%22elements%22%3A%5B%7B%22type%22%3A%22rich_text_section%22%2C%22elements%22%3A%5B%7B%22type%22%3A%22text%22%2C%22text%22%3A%22Some+message...%22%7D%5D%7D%5D%7D%5D%7D%2C%22response_url%22%3A%22https%3A%5C%2F%5C%2Fhooks.slack.com%5C%2Fapp%5C%2FT04HY6K21%5C%2F1189494145200%5C%2FFbkBAWKd2u10BV0bx2Rxknfg%22%7D"

    # test payload
    slack_url_encoded['headers']['X-Unit-Test'] = 'b64stub'
    slack_url_encoded['body'] = CREATE_TICKET_PAYLOAD

    ret = app.lambda_handler(slack_url_encoded, "")
    assert ret['statusCode'] == 200

    body_dict = decode_b64_json(ret['body'])

    payload = body_dict['payload']
    assert len(payload) == 1
    assert payload[0]['type'] == "message_action"
    assert payload[0]['token'] == "abIXST3MY2dOo9KyqrPyY0l9"
    assert payload[0]['channel'] == {"id":"D014R1SRSSZ","name":"directmessage"}
    assert payload[0]['callback_id'] == "create-ticket-from-slack-msg"
    assert payload[0]['response_url'] == "https://hooks.slack.com/app/T04HY6K21/1189494145200/FbkBAWKd2u10BV0bx2Rxknfg"

    # assert data == {'payload': ['{"type":"message_action","token":"abIXST3MY2dOo9KyqrPyY0l9","action_ts":"1591302360.305165","team":{"id":"T04HY6K21","domain":"compeat"},"user":{"id":"UPG49L0TH","name":"douglas.norment","username":"douglas.norment","team_id":"T04HY6K21"},
    # "message":{"client_msg_id":"b56103b9-ab45-4e89-a1bf-fac88a76ad90","type":"message","text":"Some message...","user":"UPG49L0TH","ts":"1591301772.000200","team":"T04HY6K21","blocks":[{"type":"rich_text","block_id":"l\\/6sd","elements":[{"type":"rich_text_section","elements":[{"type":"text","text":"Some message..."}]}]}]},
    # "response_url":"https:\\/\\/hooks.slack.com\\/app\\/T04HY6K21\\/1189494145200\\/FbkBAWKd2u10BV0bx2Rxknfg"}']}


def test_url_encoded_content_passthru(slack_url_encoded):

    CREATE_TICKET_PAYLOAD = "payload=%7B%22type%22%3A%22message_action%22%2C%22token%22%3A%22abIXST3MY2dOo9KyqrPyY0l9%22%2C%22action_ts%22%3A%221591302360.305165%22%2C%22team%22%3A%7B%22id%22%3A%22T04HY6K21%22%2C%22domain%22%3A%22compeat%22%7D%2C%22user%22%3A%7B%22id%22%3A%22UPG49L0TH%22%2C%22name%22%3A%22douglas.norment%22%2C%22username%22%3A%22douglas.norment%22%2C%22team_id%22%3A%22T04HY6K21%22%7D%2C%22channel%22%3A%7B%22id%22%3A%22D014R1SRSSZ%22%2C%22name%22%3A%22directmessage%22%7D%2C%22callback_id%22%3A%22create-ticket-from-slack-msg%22%2C%22trigger_id%22%3A%221178280893905.4610223069.9aafb644573a581f3251c8f1cff8008d%22%2C%22message_ts%22%3A%221591301772.000200%22%2C%22message%22%3A%7B%22client_msg_id%22%3A%22b56103b9-ab45-4e89-a1bf-fac88a76ad90%22%2C%22type%22%3A%22message%22%2C%22text%22%3A%22Some+message...%22%2C%22user%22%3A%22UPG49L0TH%22%2C%22ts%22%3A%221591301772.000200%22%2C%22team%22%3A%22T04HY6K21%22%2C%22blocks%22%3A%5B%7B%22type%22%3A%22rich_text%22%2C%22block_id%22%3A%22l%5C%2F6sd%22%2C%22elements%22%3A%5B%7B%22type%22%3A%22rich_text_section%22%2C%22elements%22%3A%5B%7B%22type%22%3A%22text%22%2C%22text%22%3A%22Some+message...%22%7D%5D%7D%5D%7D%5D%7D%2C%22response_url%22%3A%22https%3A%5C%2F%5C%2Fhooks.slack.com%5C%2Fapp%5C%2FT04HY6K21%5C%2F1189494145200%5C%2FFbkBAWKd2u10BV0bx2Rxknfg%22%7D"

    # ensure no errors
    slack_url_encoded['headers']['X-Unit-Test'] = 'passthru'
    slack_url_encoded['body'] = CREATE_TICKET_PAYLOAD

    ret = app.lambda_handler(slack_url_encoded, "")
    assert ret['statusCode'] == 200

    data = json.loads(ret['body'])
    assert data == {}


