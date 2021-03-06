import json
import pytest
from src import app
import urllib.parse
import base64

THREADED_LAMBDA_HEADER = 'X-Spawn-Lambda-Thread' # App only checks for presence of header
UNIT_TEST_HEADER_FLAGS = 'X-Unit-Test-Flags' # App looks for following flags

F_SKIP_THREAD_SPAWN = 'skip-thread-spawn'
F_B64_STUB = 'b64stub'
F_B64_RESP = 'b64response'
F_PASSTHRU = 'passthru' # App doesn't really look for this flag, provided for readability



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
                'X-Slack-Signature': '<OBSFUCATED>',
                # This custom header will apply to most tests
                THREADED_LAMBDA_HEADER: 'respawned-to-self-for-async-response',
                # This custom header is to prevent the thread-spawn
                UNIT_TEST_HEADER_FLAGS: F_SKIP_THREAD_SPAWN,
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
    slack_challenge_event['headers']['Content-Type'] = 'application/json'
    # This one must return with no special header flags
    del slack_challenge_event['headers'][THREADED_LAMBDA_HEADER]
    del slack_challenge_event['headers'][UNIT_TEST_HEADER_FLAGS]
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
    """Fakes a call with url-encoded content type.
    """
    slack_url_encoded = apigw_slack_base_event()
    slack_url_encoded['headers']['Content-Type'] = 'application/x-www-form-urlencoded'
    slack_url_encoded['body'] = "token=abIXST3MY2dOo9KyqrPyY0l9&team_domain=compeat&channel_name=directmessage&user_id=UPG49L0TH&command=%2Fit-list-test&text=&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT04HY6K21%2F1163195318885%2FVp4f4yPdOGF1dXe96A9E2i5U"
    return slack_url_encoded



@pytest.fixture()
def slack_event_json():
    """Fakes a call with event content.
    """
    slack_event = apigw_slack_base_event()
    slack_event['headers']['Content-Type'] = 'application/json'
    slack_event['body'] = "{\"token\":\"abIXST3MY2dOo9KyqrPyY0l9\",\"team_id\":\"T04HY6K21\",\"api_app_id\":\"A015G0J57UY\",\"event\":{\"client_msg_id\":\"b0cf9965-0a77-4a12-929c-b748c5ac6c37\",\"type\":\"message\",\"text\":\"Will you process this message now?\",\"user\":\"UPG49L0TH\",\"ts\":\"1591356390.000300\",\"team\":\"T04HY6K21\",\"blocks\":[{\"type\":\"rich_text\",\"block_id\":\"IMJ\",\"elements\":[{\"type\":\"rich_text_section\",\"elements\":[{\"type\":\"text\",\"text\":\"Will you process this message now?\"}]}]}],\"channel\":\"D014R1SRSSZ\",\"event_ts\":\"1591356390.000300\",\"channel_type\":\"im\"},\"type\":\"event_callback\",\"event_id\":\"Ev014X2TSWDR\",\"event_time\":1591356390,\"authed_users\":[\"U014BLFS3CP\"]}"
    return slack_event




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
    
    # test challenge - must return with no special header flags
    ret = app.lambda_handler(apigw_slack_challenge_event, "")
    assert ret['statusCode'] == 200

    data = json.loads(ret['body'])
    assert data == {'challenge': 'somerandomdigits'}


def test_unknown_content_type(slack_unknown_content):

    # test unknown content
    slack_unknown_content['headers'][UNIT_TEST_HEADER_FLAGS] = ' '.join([F_PASSTHRU, F_SKIP_THREAD_SPAWN])
    ret = app.lambda_handler(slack_unknown_content, "")
    assert ret['statusCode'] == 415

    data = json.loads(ret['body'])
    assert data == {"Error": "Unexpected Content-Type (null)"}

@pytest.mark.skip(reason="Currently not using separate thread to respond to slack")
def test_immediate_slack_response(caplog, slack_url_encoded):

    slack_url_encoded['headers'][UNIT_TEST_HEADER_FLAGS] = ' '.join([F_B64_STUB, F_SKIP_THREAD_SPAWN])
    # Test initial (non-respwaned) call
    del slack_url_encoded['headers'][THREADED_LAMBDA_HEADER]
    ret = app.lambda_handler(slack_url_encoded, "")
    assert ret['statusCode'] == 200

    # Use log to determine if immediate redirection spawn would have occurred 
    assert 'Returning 200 OK to slack' in caplog.text, 'Immediate return not made'


def decode_b64_json_if_present(ret_body):
    """ utility to take ret['body']={'req_body_base64' : 'some64string=='}
        and return dictionary """

    b64_body = (json.loads(ret_body or {})).get('req_body_base64')
    if b64_body:
        b64_bytes = b64_body.encode('utf-8')
        msg_bytes = base64.b64decode(b64_bytes)
        msg = msg_bytes.decode('utf-8')
        body_dict = json.loads(msg)
    else:
        body_dict = json.loads(ret_body)

    return body_dict


def test_url_encoded_content(slack_url_encoded):

    # https://api.slack.com/interactivity/slash-commands
    # sends Content-type: application/x-www-form-urlencoded in POST "body"

    # test payload
    slack_url_encoded['headers'][UNIT_TEST_HEADER_FLAGS] = ' '.join([F_B64_STUB, F_SKIP_THREAD_SPAWN])
    ret = app.lambda_handler(slack_url_encoded, "")
    assert ret['statusCode'] == 200

    body_dict = decode_b64_json_if_present(ret['body'])

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
    slack_url_encoded['headers'][UNIT_TEST_HEADER_FLAGS] = ' '.join([F_PASSTHRU, F_SKIP_THREAD_SPAWN])

    ret = app.lambda_handler(slack_url_encoded, "")
    assert ret['statusCode'] == 200

    data = json.loads(ret['body'])
    assert data == {}


def test_payload_content_create_ticket(slack_url_encoded):

    # https://api.slack.com/interactivity/shortcuts/using#message_shortcuts
    # - message short-cuts

    CREATE_TICKET_PAYLOAD = "payload=%7B%22type%22%3A%22message_action%22%2C%22token%22%3A%22abIXST3MY2dOo9KyqrPyY0l9%22%2C%22action_ts%22%3A%221591302360.305165%22%2C%22team%22%3A%7B%22id%22%3A%22T04HY6K21%22%2C%22domain%22%3A%22compeat%22%7D%2C%22user%22%3A%7B%22id%22%3A%22UPG49L0TH%22%2C%22name%22%3A%22douglas.norment%22%2C%22username%22%3A%22douglas.norment%22%2C%22team_id%22%3A%22T04HY6K21%22%7D%2C%22channel%22%3A%7B%22id%22%3A%22D014R1SRSSZ%22%2C%22name%22%3A%22directmessage%22%7D%2C%22callback_id%22%3A%22create-ticket-from-slack-msg%22%2C%22trigger_id%22%3A%221178280893905.4610223069.9aafb644573a581f3251c8f1cff8008d%22%2C%22message_ts%22%3A%221591301772.000200%22%2C%22message%22%3A%7B%22client_msg_id%22%3A%22b56103b9-ab45-4e89-a1bf-fac88a76ad90%22%2C%22type%22%3A%22message%22%2C%22text%22%3A%22Some+message...%22%2C%22user%22%3A%22UPG49L0TH%22%2C%22ts%22%3A%221591301772.000200%22%2C%22team%22%3A%22T04HY6K21%22%2C%22blocks%22%3A%5B%7B%22type%22%3A%22rich_text%22%2C%22block_id%22%3A%22l%5C%2F6sd%22%2C%22elements%22%3A%5B%7B%22type%22%3A%22rich_text_section%22%2C%22elements%22%3A%5B%7B%22type%22%3A%22text%22%2C%22text%22%3A%22Some+message...%22%7D%5D%7D%5D%7D%5D%7D%2C%22response_url%22%3A%22https%3A%5C%2F%5C%2Fhooks.slack.com%5C%2Fapp%5C%2FT04HY6K21%5C%2F1189494145200%5C%2FFbkBAWKd2u10BV0bx2Rxknfg%22%7D"

    # test payload
    slack_url_encoded['headers'][UNIT_TEST_HEADER_FLAGS] = ' '.join([F_B64_STUB, F_SKIP_THREAD_SPAWN])
    slack_url_encoded['body'] = CREATE_TICKET_PAYLOAD

    ret = app.lambda_handler(slack_url_encoded, "")
    assert ret['statusCode'] == 200

    body_dict = decode_b64_json_if_present(ret['body'])

    payload = body_dict['payload']
    assert body_dict['slack_event_type'] == "shortcut"

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
    slack_url_encoded['headers'][UNIT_TEST_HEADER_FLAGS] = ' '.join([F_PASSTHRU, F_SKIP_THREAD_SPAWN])
    slack_url_encoded['body'] = CREATE_TICKET_PAYLOAD

    ret = app.lambda_handler(slack_url_encoded, "")
    assert ret['statusCode'] == 200

    data = json.loads(ret['body'])
    assert data == {} or 'CUTOFF ERROR' in data


def test_event_body(slack_event_json):

    # https://api.slack.com/events-api
    # - event:: Content-type: application/json: { ...  "event": { "type": "name_of_event" } }

    slack_event_json['headers'][UNIT_TEST_HEADER_FLAGS] = ' '.join([F_B64_STUB, F_SKIP_THREAD_SPAWN])

    ret = app.lambda_handler(slack_event_json, "")
    assert ret['statusCode'] == 200

    body_dict = decode_b64_json_if_present(ret['body'])

    assert body_dict == {
          'api_app_id': 'A015G0J57UY',                                                                                                                                                                     
          'authed_users': ['U014BLFS3CP'],
          'event': {'blocks': [
                        {'block_id': 'IMJ',
                         'elements': [
                            {'elements': [
                                {'text': 'Will you process this message now?','type': 'text'}],
                             'type': 'rich_text_section'}
                          ],
                          'type': 'rich_text'}],
                    'channel': 'D014R1SRSSZ',
                    'channel_type': 'im',
                    'client_msg_id': 'b0cf9965-0a77-4a12-929c-b748c5ac6c37',
                    'event_ts': '1591356390.000300',
                    'team': 'T04HY6K21',
                    'text': 'Will you process this message now?',
                    'ts': '1591356390.000300',
                    'type': 'message',
                    'user': 'UPG49L0TH'},
          'event_id': 'Ev014X2TSWDR',
          'event_time': 1591356390,
          'slack_event_type': 'json-string',
          'team_id': 'T04HY6K21',
          'token': 'abIXST3MY2dOo9KyqrPyY0l9',
          'type': 'event_callback',
    }


def test_event_body_passthru(slack_event_json):

    """ ensure the code can execute all the way through without error """

    slack_event_json['headers'][UNIT_TEST_HEADER_FLAGS] = ' '.join([F_PASSTHRU, F_SKIP_THREAD_SPAWN])

    ret = app.lambda_handler(slack_event_json, "")
    assert ret['statusCode'] == 200

    body_dict = decode_b64_json_if_present(ret['body'])

    assert body_dict == {} # or 'CUTOFF ERROR' in body_dict


@pytest.mark.skip(reason="TBD")
def test_event_body_sample_msg(slack_event_json):

    slack_event_json['headers'][UNIT_TEST_HEADER_FLAGS] = ' '.join([F_B64_RESP, F_SKIP_THREAD_SPAWN])
    slack_event_json['body'] = "{\"token\":\"abIXST3MY2dOo9KyqrPyY0l9\",\"team_id\":\"T04HY6K21\",\"api_app_id\":\"A015G0J57UY\",\"event\":{\"client_msg_id\":\"b0cf9965-0a77-4a12-929c-b748c5ac6c37\",\"type\":\"message\",\"text\":\"Will you process this message now?\",\"user\":\"UPG49L0TH\",\"ts\":\"1591356390.000300\",\"team\":\"T04HY6K21\",\"blocks\":[{\"type\":\"rich_text\",\"block_id\":\"IMJ\",\"elements\":[{\"type\":\"rich_text_section\",\"elements\":[{\"type\":\"text\",\"text\":\"Will you process this message now?\"}]}]}],\"channel\":\"D014R1SRSSZ\",\"event_ts\":\"1591356390.000300\",\"channel_type\":\"im\"},\"type\":\"event_callback\",\"event_id\":\"Ev014X2TSWDR\",\"event_time\":1591356390,\"authed_users\":[\"U014BLFS3CP\"]}"

    ret = app.lambda_handler(slack_event_json, "")
    assert ret['statusCode'] == 200

    body_dict = decode_b64_json_if_present(ret['body'])

    assert body_dict == {} # or 'CUTOFF ERROR' in body_dict

