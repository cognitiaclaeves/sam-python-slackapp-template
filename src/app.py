"""
Slack chat-bot Lambda handler.
Modified from: https://github.com/Beartime234/sam-python-slackapp-template
"""

# Module Imports
import os
import logging
import json
import time
import hmac
import hashlib
import json
import urllib.parse
import base64
import threading
# import multiprocessing
# import requests
from slack import WebClient as Slack_WebClient
from http.client import UNSUPPORTED_MEDIA_TYPE, BAD_REQUEST
from http.client import OK as OK_200

# Local imports
import helpers
from version import __version__

# Get Environment Variables
# This is declared globally because as this is useful for tests etc.
SECRETS_NAME = os.environ["SECRETS_NAME"]
STAGE = os.environ["STAGE"]

CUTOFF = os.environ.get('SLACK_LAMBDA_MASTER_CUTOFF')
THREADED_LAMBDA_HEADER = 'X-Spawn-Lambda-Thread'
UNIT_TEST_HEADER_FLAGS = 'X-Unit-Test-Flags'

F_SKIP_THREAD_SPAWN = 'skip-thread-spawn'
F_B64_STUB = 'b64stub'
F_B64_RESP = 'b64response'


# Set up logging here info so we should get the
LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.DEBUG)

# Ignore non important logs from botocore and boto3 cause they talk to much
logging.getLogger('botocore').setLevel(logging.CRITICAL)
logging.getLogger('boto3').setLevel(logging.CRITICAL)


# Grab secrets for the application.
SECRETS = json.loads(helpers.get_secrets(SECRETS_NAME))

SLACK_WEBCLIENT = Slack_WebClient(SECRETS["BOT_TOKEN"])



def obscure_dict(some_dict):
    ret = {}
    for each_key in some_dict:
        val = some_dict[each_key]
        ret[each_key] = '{}..{}..{}'.format( val[0:2], len(val), val[-2:] )
    return ret


def encode_b64_dict(response_dict):
    """ utility to take dictionary 
        and return {'req_body_base64' : 'some64string=='} """

    body_json = json.dumps(response_dict)
    body_bytes = body_json.encode('utf-8')
    body_base64 = base64.b64encode(body_bytes)

    ret = {
        'req_body_base64': '{}'.format(body_base64.decode('utf-8'))
    }

    return ret


    # if "bot_id" in slack_body_dict:
    #     logging.warning("Ignore bot event")
    # else:
    #     # Get the text of the message the user sent to the bot,
    #     # and reverse it.
    #     ret = process_event(slack_event_dict)

    #     slack_event_dict = {}
    #     if slack_event_dict:
    #         # Get the ID of the channel where the message was posted.
    #         channel_id = slack_event_dict["channel"]

    #         response = slack_client.chat_postMessage(
    #             channel=channel_id,
    #             text=ret
    #         )

    #         LOGGER.debug('Response: {}'.format(response))


def process_not_implemented(**kwargs):

    """ default process function - return not implemented """

    ret_dict = { 'function_return': 'not-implemented',
                 'slack_response': {} }

    return ret_dict


def process_event(**kwargs):

    """ process slack event """

    slack_event_dict = kwargs['body']['event']

    ret_dict = process_not_implemented()

    if 'bot_id' in slack_event_dict:
        LOGGER.debug('Ignoring event ({}) caused by bot chatter.'.format(slack_event_dict["type"]))

        ret_dict = { 'function_return': 'ignored bot chatter',
                     'slack_response': {} }

    else:    
        LOGGER.debug('Will process event: {}'.format(slack_event_dict["type"]))

        if slack_event_dict["type"] == "message":
            text = slack_event_dict.get("text")

            if UNIT_TEST_HEADER_FLAGS in kwargs['headers']:
                # If unit-test flag is detected, reverse the text

                if text:
                    reversed_text = text[::-1]

                    channel_id = slack_event_dict["channel"]
                    response = SLACK_WEBCLIENT.chat_postMessage(
                                    channel=channel_id, text=reversed_text )

                    ret_dict = { 'function_return': reversed_text,
                                 'slack_response': response }
    return ret_dict


    

def process_shortcut(**kwargs):

    """ process slack shortcut (message / global) """

    ret_dict = process_not_implemented()

    return ret_dict


def process_slash_cmd(**kwargs):

    """ process slack slash command """

    ret_dict = process_not_implemented()

    return ret_dict



def lambda_handler(api_event, api_context):
    """Handle an incoming HTTP request from a Slack chat-bot.
    """

    if type(SECRETS) is not dict:
        raise TypeError("Secrets response must be a dictionary.")

    if CUTOFF == True or CUTOFF == '1':
        LOGGER.warning("Master cutoff switch is on. Exiting lambda.")
        return helpers.form_response(OK_200, {'CUTOFF ERROR': 'Master cutoff switch is engaged. Exiting.'})


    LOGGER.info(f" -- Startup Information Version: {__version__}")
    LOGGER.debug(f"Secret Information: {obscure_dict(SECRETS)}")

    apievent_ContentType = (api_event.get('headers') or {}).get('Content-Type') or 'null'
    request_headers = api_event["headers"]
 

    # First and foremost, process challenge event, if sent:

    # This is to appease the slack challenge event that is sent
    # when subscribing to the slack event API. You can read more
    # here https://api.slack.com/events/url_verification

    if apievent_ContentType == 'application/json':
        apievent_body_ = json.loads(api_event.get('body') or {})

        if is_challenge(apievent_body_):
            challenge_response_body = {
                "challenge": apievent_body_["challenge"]
            }
            LOGGER.info('Responding to challenge event.')
            return helpers.form_response(OK_200, challenge_response_body)


    # *** DO NOT DELETE BELOW, REVISIT IN FUTURE ***

    # Responding immediately is best practice recommended by Slack

    # If not challenge, then immediately return OK
    #    when customer header THREADED_LAMBDA_HEADER is not present

    # If SKIP_THREAD_SPAWN is not sent in custom header UNIT_TEST_HEADER_FLAGS,
    #    then spawn a new thread with the payload

    # Otherwise, if THREADED_LAMBDA_HEADER is not present, then process payload


    # To test behavior after the spawn, include THREADED_LAMBDA_HEADER
    # To test immediate response, do not include THREADED_LAMBDA_HEADER


    # if THREADED_LAMBDA_HEADER not in request_headers:
    #     # Skip creating new thread if UNIT_TEST_HEADER_FLAGS indicates to not do so
    #     if F_SKIP_THREAD_SPAWN not in (request_headers.get(UNIT_TEST_HEADER_FLAGS) or ''):

    #         # Spawn new thread with special thread header
    #         api_event['headers'][THREADED_LAMBDA_HEADER] = 'respawned-to-self-for-async-response'
    #         LOGGER.info('Launching separate thread for lambda to process request!')

    #         # p = multiprocessing.Process(target=lambda_handler, args=(api_event, api_context, ))
    #         # p.start()
    #         # p.join()

    #         t = threading.Thread(target=lambda_handler, args=(api_event, api_context), daemon=False )
    #         t.start()

    #         # I couldn't get this to work like I wanted it to.
    #         # I wanted to spawn an autonomous thread that would finish running after this thread returns (dies)
    #         # But I wasn't able to figure out if this was even possible to do.

    #         # Since it currently executes "fast enough", I'm just going to wait for the processing to finish
    #         t.join()
    #         # https://stackoverflow.com/questions/53386968/multithreading-in-aws-lambda-using-python3
        
    #     LOGGER.info('Returning 200 OK to slack')
    #     return helpers.form_response(OK_200, {})


    # to test a long-running process doesn't die before the 'parent' thread:
    # for i in range(0, 29000000):
    #     pass

    # *** DO NOT DELETE ABOVE, REVISIT IN FUTURE ***

    LOGGER.info(f'Detected Content-Type: {apievent_ContentType}')

    # At this stage, this could be multiple things (see notes below), so log entire dictionary as json
    LOGGER.debug('api_event: {}'.format(json.dumps(api_event)))


    # Set default processing function
    process_function = process_not_implemented

    # load dict with payload, set processing function to match body contents

    # Note: Being a little sloppy with this initially;
    #       It is possible I will need to be more specific about different slack calls later
    #       This may manifest with slack calls being processed with the wrong function 

    if apievent_ContentType in ('application/x-www-form-urlencoded'):
        apievent_body_ = urllib.parse.parse_qs(api_event.get('body'))
        apievent_body_['slack_event_type'] = 'slash-command'
        process_function = process_event

        if 'payload' in apievent_body_:
            new_apievent_body_ = { 'payload' : [] }
            LOGGER.debug('apievent_body_: {}'.format(apievent_body_))

            for each_el in apievent_body_.get('payload') or {}:
                new_apievent_body_['payload'].append( json.loads(each_el) )
            
            apievent_body_ = new_apievent_body_
            apievent_body_['slack_event_type'] = 'shortcut'
            process_function = process_shortcut

            LOGGER.debug('payload based apievent_body: {}'.format(apievent_body_))

    elif apievent_ContentType in ('application/json'):
        apievent_body_ = api_event.get('body')
        try:
            apievent_body_ = json.loads(apievent_body_)
            apievent_body_['slack_event_type'] = 'json-string'
        except TypeError:
            pass
        if 'slack_event_type' not in apievent_body_:
            apievent_body_['slack_event_type'] = 'json'
    else:
        LOGGER.error(f'Content-Type unexpected: {apievent_ContentType}')
        return helpers.form_response(UNSUPPORTED_MEDIA_TYPE, {"Error": f"Unexpected Content-Type ({apievent_ContentType})"})

    LOGGER.debug('body({}): {}'.format(apievent_ContentType, json.dumps(apievent_body_)))

    slack_event_dict = apievent_body_.get("event") or {}
    LOGGER.debug('event dict: {}'.format(json.dumps(slack_event_dict)))


    # Grab relevant information form the api_event
    # slack_body_raw = api_event["body"]
    # slack_body_dict = json.loads(slack_body_raw)

    slack_body_dict = apievent_body_
    

    if F_B64_STUB in (request_headers.get(UNIT_TEST_HEADER_FLAGS) or ''):
        # If F_B64_STUB is present in request header UNIT_TEST_HEADER_FLAGS,
        #    return the body dict as b64 encoded json to test exepected data structure

        stub_return = encode_b64_dict(apievent_body_)
        return helpers.form_response(OK_200, stub_return)

    # If the stage is production make sure that we are receiving events from slack otherwise we don't care
    if STAGE is "prod":
        LOGGER.debug(f"We are in production. So we are going to verify the request.")
        if not verify_request(request_headers["X-Slack-Signature"], request_headers["X-Slack-Request-Timestamp"],
                              slack_body_raw, SECRETS["SIGNING_SECRET"]):
            return helpers.form_response(BAD_REQUEST, {"Error": "Bad Request Signature"})


    # If cutoff is half-engaged, terminate execution here

    # if CUTOFF == '.5':
    #     LOGGER.debug("Master cutoff switch is half-engaged. Exiting except for unit tests.")
    #     return helpers.form_response(OK_200, {'CUTOFF ERROR': 'Master cutoff switch is half-engaged. Exiting except for unit tests.'})


    # There are different types of payloads.
    # - slash-commands
    # - message-shortcuts
    # - challenge
    # - events
    # See unit tests for more information.

    # call appropriate processing function for slack call
    if CUTOFF:
        skip_slack_call = True
    else:
        skip_slack_call = False

    ret = process_function( body=apievent_body_, skip_slack=skip_slack_call )





    # TODO - Remove
    # b64_body = (json.loads(ret_body or {})).get('req_body_base64')
    # if b64_body:
    #     b64_bytes = b64_body.encode('utf-8')
    #     msg_bytes = base64.b64decode(b64_bytes)
    #     msg = msg_bytes.decode('utf-8')
    #     body_dict = json.loads(msg)
    # else:
    #     body_dict = json.loads(ret_body)

    # return body_dict

    # def b64_encode_dict()



    # if F_B64_RESP in (request_headers.get(UNIT_TEST_HEADER_FLAGS) or ''):
    #     # If F_B64_RESP is present in request header UNIT_TEST_HEADER_FLAGS,
    #     #    return a response dict as b64 encoded json to test exepected behavior

    #     lambda_response = encode_b64_dict( ret )
    #     return helpers.form_response(OK_200, lambda_response)



    # # If there is a request header indicating a unit test,
    # #    then return the body dict as b64 encoded json
    # #    to test if data is exactly as expected

    # body_json = json.dumps(apievent_body_)
    # body_bytes = body_json.encode('utf-8')
    # body_base64 = base64.b64encode(body_bytes)

    # stub_return = {
    #     'req_body_base64': '{}'.format(body_base64.decode('utf-8'))
    # }
    # return helpers.form_response(OK_200, stub_return)



    # This parses the slack body dict to get the event JSON
    # this will hold information about the text and
    # the user who did it.



    # Build the slack client. This allows us make slack API calls
    # read up on the python-slack-client here. We get this from
    # AWS secrets manager. https://github.com/slackapi/python-slackclient
    # slack_client = Slack_WebClient(secrets["BOT_TOKEN"])

    # We need to discriminate between events generated by 
    # the users, which we want to process and handle, 
    # and those generated by the bot.

    # if "bot_id" in slack_body_dict:
    #     logging.warning("Ignore bot event")
    # else:
    #     # Get the text of the message the user sent to the bot,
    #     # and reverse it.
    #     ret = process_event(slack_event_dict)

    #     slack_event_dict = {}
    #     if slack_event_dict:
    #         # Get the ID of the channel where the message was posted.
    #         channel_id = slack_event_dict["channel"]

    #         response = slack_client.chat_postMessage(
    #             channel=channel_id,
    #             text=ret
    #         )

    #         LOGGER.debug('Response: {}'.format(response))

    # Everything went fine return a good response.

    if CUTOFF == '.5':
        LOGGER.warning("Master cutoff switch is half-engaged. Exiting except for unit tests.")
        return helpers.form_response(OK_200, {'CUTOFF ERROR': 'Master cutoff switch is half-engaged. Exiting except for unit tests.'})
    else:
        return helpers.form_response(OK_200, {})


def is_challenge(slack_event_body: dict) -> bool:
    """Is the event a challenge from slack? If yes return the correct response to slack

    Args:
        slack_event_body (dict): The slack event JSON

    Returns:
        returns True if it is a slack challenge event returns False otherwise
    """
    if "challenge" in slack_event_body:
        LOGGER.info("Challenge Data: {}".format(slack_event_body['challenge']))
        return True
    return False


def verify_request(slack_signature: str, slack_timestamp: str, slack_event_body: str, app_signing_secret) -> bool:
    """Does the header sent in the request match the secret token.

    If it doesn't it may be an insecure request from someone trying to pose as your
    application. You can read more about the url-verification and why this is necessary
    here https://api.slack.com/docs/verifying-requests-from-slack

    Args:
        app_signing_secret (str): The apps local signing secret that is given by slack to compare with formulated.
        slack_signature (str): The header of the http_request from slack X-Slack-Signature
        slack_timestamp (str): The header of the http_request from slack X-Slack-Request-Timestamp
        slack_event_body (str): The slack event body that must be formulated as a string

    Returns:
        A boolean. If True the request was valid if False request was not valid.
    """
    if abs(time.time() - float(slack_timestamp)) > 60 * 5:
        # The request is older then 5 minutes
        LOGGER.warning(f"Request verification failed. Timestamp was over 5 mins old for the request")
        return False
    sig_basestring = f"v0:{slack_timestamp}:{slack_event_body}".encode('utf-8')
    slack_signing_secret = bytes(app_signing_secret, 'utf-8')
    my_signature = 'v0=' + hmac.new(slack_signing_secret, sig_basestring, hashlib.sha256).hexdigest()
    if hmac.compare_digest(my_signature, slack_signature):
        return True
    else:
        LOGGER.warning(f"Verification failed. my_signature: {my_signature} slack_signature: {slack_signature}")
        return False
