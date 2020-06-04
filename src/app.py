"""
Slack chat-bot Lambda handler.
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
# import requests
from slack import WebClient as SlackClient
from http.client import UNSUPPORTED_MEDIA_TYPE, BAD_REQUEST
from http.client import OK as OK_200

# Local imports
import helpers
from version import __version__

# Get Environment Variables
# This is declared globally because as this is useful for tests etc.
SECRETS_NAME = os.environ["SECRETS_NAME"]
STAGE = os.environ["STAGE"]

# Set up logging here info so we should get the
LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.DEBUG)

# Ignore non important logs from botocore and boto3 cause they talk to much
logging.getLogger('botocore').setLevel(logging.CRITICAL)
logging.getLogger('boto3').setLevel(logging.CRITICAL)


def process_event(slack_event_dict):
        LOGGER.debug('Will process: {}'.format(slack_event_dict))
        text = slack_event_dict.get("text")
        if text:
            reversed_text = text[::-1]
            return reversed_text
        else:
            return '(No text detected.)'


def obscure_dict(some_dict):
    ret = {}
    for each_key in some_dict:
        val = some_dict[each_key]
        ret[each_key] = '{}..{}..{}'.format( val[0:2], len(val), val[-2:] )
    return ret


def lambda_handler(api_event, api_context):
    """Handle an incoming HTTP request from a Slack chat-bot.
    """

    # Grab secrets for the application.
    secrets = json.loads(helpers.get_secrets(SECRETS_NAME))
    if type(secrets) is not dict:
        raise TypeError("Secrets response must be a dictionary.")

    LOGGER.info(f" -- Startup Information Version: {__version__}")
    LOGGER.debug(f"Secret Information: {obscure_dict(secrets)}")

    apievent_ContentType = (api_event.get('headers') or {}).get('Content-Type') or 'null'

    LOGGER.info(f'Detected Content-Type: {apievent_ContentType}')

    # At this stage, this could be multiple things (see notes below), so log entire dictionary as json
    LOGGER.debug('api_event: {}'.format(json.dumps(api_event)))

    # load dict with payload
    if apievent_ContentType in ('application/x-www-form-urlencoded'):
        apievent_body_ = urllib.parse.parse_qs(api_event.get('body'))
        apievent_body_['slack_event_type'] = 'slash-command'
        if 'payload' in apievent_body_:
            new_apievent_body_ = { 'payload' : [] }
            LOGGER.debug('apievent_body_: {}'.format(apievent_body_))

            for each_el in apievent_body_.get('payload') or {}:
                new_apievent_body_['payload'].append( json.loads(each_el) )
            
            apievent_body_ = new_apievent_body_
            apievent_body_['slack_event_type'] = 'shortcut'

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
    request_headers = api_event["headers"]

    if request_headers.get('X-Unit-Test') == 'b64stub':
        # If there is a request header indicating a unit test,
        #    then return the body dict as b64 encoded json
        #    to test if data is exactly as expected

        body_json = json.dumps(apievent_body_)
        body_bytes = body_json.encode('utf-8')
        body_base64 = base64.b64encode(body_bytes)

        stub_return = {
            'req_body_base64': '{}'.format(body_base64.decode('utf-8'))
        }
        return helpers.form_response(OK_200, stub_return)

    # If the stage is production make sure that we are receiving events from slack otherwise we don't care
    if STAGE is "prod":
        LOGGER.debug(f"We are in production. So we are going to verify the request.")
        if not verify_request(request_headers["X-Slack-Signature"], request_headers["X-Slack-Request-Timestamp"],
                              slack_body_raw, secrets["SIGNING_SECRET"]):
            return helpers.form_response(BAD_REQUEST, {"Error": "Bad Request Signature"})

    # This is to appease the slack challenge event that is sent
    # when subscribing to the slack event API. You can read more
    # here https://api.slack.com/events/url_verification
    if is_challenge(slack_body_dict):
        challenge_response_body = {
            "challenge": slack_body_dict["challenge"]
        }
        return helpers.form_response(OK_200, challenge_response_body)


    # There are different types of payloads

    # https://api.slack.com/interactivity/slash-commands
    # sends Content-type: application/x-www-form-urlencoded in POST "body"

    # https://api.slack.com/interactivity/shortcuts/using#message_shortcuts
    # - message short-cuts
    # 

    # https://api.slack.com/events-api
    # - challenge:: Content-type: application/json: { "token" : "...", "challenge": "...", "type": "url_verification" }
    # - event:: Content-type: application/json: { ...  "event": { "type": "name_of_event" } }



    # This parses the slack body dict to get the event JSON
    # this will hold information about the text and
    # the user who did it.




    # Build the slack client. This allows us make slack API calls
    # read up on the python-slack-client here. We get this from
    # AWS secrets manager. https://github.com/slackapi/python-slackclient
    slack_client = SlackClient(secrets["BOT_TOKEN"])

    # We need to discriminate between events generated by 
    # the users, which we want to process and handle, 
    # and those generated by the bot.
    if "bot_id" in slack_body_dict:
        logging.warning("Ignore bot event")
    else:
        # Get the text of the message the user sent to the bot,
        # and reverse it.
        ret = process_event(slack_event_dict)

        if slack_event_dict:
            # Get the ID of the channel where the message was posted.
            channel_id = slack_event_dict["channel"]

            # This makes the actual api call
            slack_client.api_call(
                "chat.postMessage",
                channel=channel_id,
                text=ret
            )

    # Everything went fine return a good response.
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
