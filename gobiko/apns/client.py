import importlib
import json
import jwt
import time
import uuid

from collections import namedtuple
from contextlib import closing
from hyper import HTTP20Connection

# from .exceptions import (
#     InternalException,
#     ImproperlyConfigured,
#     PayloadTooLarge,
#     BadDeviceToken,
#     PartialBulkMessage
# )

class APNsException(Exception):
    def __str__(self):
        return '{e.__class__.__name__}: {e.__doc__}'.format(e=self)


class InternalException(APNsException):
    pass


class ImproperlyConfigured(APNsException):
    pass


class BadCollapseId(APNsException):
    "The collapse identifier exceeds the maximum allowed size"
    pass


class BadDeviceToken(APNsException):
    "The specified device token was bad. Verify that the request contains a valid token and that the token matches the environment."
    pass


class BadExpirationDate(APNsException):
    "The apns-expiration value is bad."
    pass


class BadMessageId(APNsException):
    "The apns-id value is bad."
    pass

class PartialBulkMessage(APNsException):
    def __init__(self, message, bad_registration_ids):
        super(APNsException, self).__init__(message)
        self.bad_registration_ids = bad_registration_ids

class BadPriority(APNsException):
    "The apns-priority value is bad."
    pass


class BadTopic(APNsException):
    "The apns-topic was invalid."
    pass


class DeviceTokenNotForTopic(APNsException):
    "The device token does not match the specified topic."
    pass


class DuplicateHeaders(APNsException):
    "One or more headers were repeated."
    pass


class IdleTimeout(APNsException):
    "Idle time out."
    pass


class MissingDeviceToken(APNsException):
    "The device token is not specified in the request :path. Verify that the :path header contains the device token."
    pass


class MissingTopic(APNsException):
    "The apns-topic header of the request was not specified and was required. The apns-topic header is mandatory when the client is connected using a certificate that supports multiple topics."
    pass


class PayloadEmpty(APNsException):
    "The message payload was empty."
    pass


class TopicDisallowed(APNsException):
    "Pushing to this topic is not allowed."
    pass


class BadCertificate(APNsException):
    "The certificate was bad."
    pass


class BadCertificateEnvironment(APNsException):
    "The client certificate was for the wrong environment."
    pass


class ExpiredProviderToken(APNsException):
    "The provider token is stale and a new token should be generated."
    pass


class Forbidden(APNsException):
    "The specified action is not allowed."
    pass


class InvalidProviderToken(APNsException):
    "The provider token is not valid or the token signature could not be verified."
    pass


class MissingProviderToken(APNsException):
    "No provider certificate was used to connect to APNs and Authorization header was missing or no provider token was specified."
    pass


class BadPath(APNsException):
    "The request contained a bad :path value."
    pass


class MethodNotAllowed(APNsException):
    "The specified :method was not POST."
    pass


class Unregistered(APNsException):
    "The device token is inactive for the specified topic. Expected HTTP/2 status code is 410; see Table 8-4."
    pass


class PayloadTooLarge(APNsException):
    "The message payload was too large. See Creating the Remote Notification Payload for details on maximum payload size."
    pass


class TooManyProviderTokenUpdates(APNsException):
    "The provider token is being updated too often."
    pass


class TooManyRequests(APNsException):
    "Too many requests were made consecutively to the same device token."
    pass


class InternalServerError(APNsException):
    "An internal server error occurred."
    pass


class ServiceUnavailable(APNsException):
    "The service is unavailable."
    pass


class Shutdown(APNsException):
    "The server is shutting down."
    pass



#from .utils import validate_private_key, wrap_private_key
from textwrap import wrap

def validate_private_key(private_key):
    mode = "start"
    for line in private_key.split("\n"):
        if mode == "start":
            if "BEGIN PRIVATE KEY" in line:
                mode = "key"
        elif mode == "key":
            if "END PRIVATE KEY" in line:
                mode = "end"
                break
    if mode != "end":
        raise Exception("The auth key provided is not valid")


def wrap_private_key(private_key):
    # Wrap key to 64 lines
    comps = private_key.split("\n")
    wrapped_key = "\n".join(wrap(comps[1], 64))
    return "\n".join([comps[0], wrapped_key, comps[2]])


ALGORITHM = 'ES256'
SANDBOX_HOST = 'api.development.push.apple.com:443'
PRODUCTION_HOST = 'api.push.apple.com:443'
MAX_NOTIFICATION_SIZE = 4096

APNS_RESPONSE_CODES = {
    'Success': 200,
    'BadRequest': 400,
    'TokenError': 403, 
    'MethodNotAllowed': 405,
    'TokenInactive': 410,
    'PayloadTooLarge': 413,
    'TooManyRequests': 429,
    'InternalServerError': 500, 
    'ServerUnavailable': 503,
}
APNSResponseStruct = namedtuple('APNSResponseStruct', APNS_RESPONSE_CODES.keys())
APNSResponse = APNSResponseStruct(**APNS_RESPONSE_CODES)


class APNsClient(object):

    def __init__(self, team_id, auth_key_id, 
            auth_key=None, auth_key_filepath=None, bundle_id=None, use_sandbox=False, force_proto=None, wrap_key=False
        ):

        if not (auth_key_filepath or auth_key):
            raise ImproperlyConfigured(
                'You must provide either an auth key or a path to a file containing the auth key'
            )

        if not auth_key:
            try:
                with open(auth_key_filepath, "r") as f:
                    auth_key = f.read()

            except Exception as e:
                raise ImproperlyConfigured("The APNS auth key file at %r is not readable: %s" % (auth_key_filepath, e))

        validate_private_key(auth_key)
        if wrap_key:
            auth_key = wrap_private_key(auth_key) # Some have had issues with keys that aren't wrappd to 64 lines

        self.team_id = team_id
        self.bundle_id = bundle_id
        self.auth_key = auth_key
        self.auth_key_id = auth_key_id
        self.force_proto = force_proto
        self.host = SANDBOX_HOST if use_sandbox else PRODUCTION_HOST

    def send_message(self, registration_id, alert, **kwargs):
        return self._send_message(registration_id, alert, **kwargs)

    def send_bulk_message(self, registration_ids, alert, **kwargs):
        good_registration_ids = []
        bad_registration_ids = []

        with closing(self._create_connection()) as connection:
            auth_token = self._create_token()

            for registration_id in registration_ids:
                try:
                    res = self._send_message(registration_id, alert, connection=connection, auth_token=auth_token, **kwargs)
                    good_registration_ids.append(registration_id)
                except:
                    bad_registration_ids.append(registration_id)

        if not bad_registration_ids:
            return res

        elif not good_registration_ids:
            raise BadDeviceToken("None of the registration ids were accepted"
                                 "Rerun individual ids with ``send_message()``"
                                 "to get more details about why")

        else:
            raise PartialBulkMessage(
                "Some of the registration ids were accepted. Rerun individual "
                "ids with ``send_message()`` to get more details about why. "
                "The ones that failed: \n:"
                "{bad_string}\n"
                "The ones that were pushed successfully: \n:"
                "{good_string}\n".format(
                    bad_string="\n".join(bad_registration_ids),
                    good_string = "\n".join(good_registration_ids)
                ),
                bad_registration_ids
            )

    def _create_connection(self):
        return HTTP20Connection(self.host, force_proto=self.force_proto)

    def _create_token(self):
        token = jwt.encode(
            {
                'iss': self.team_id,
                'iat': time.time()
            },
            self.auth_key,
            algorithm= ALGORITHM,
            headers={
                'alg': ALGORITHM,
                'kid': self.auth_key_id,
            }
        )
        return token.decode('ascii')

    def _send_message(self, registration_id, alert, 
            badge=None, sound=None, category=None, content_available=False,
            mutable_content=False,
            action_loc_key=None, loc_key=None, loc_args=[], extra={}, 
            identifier=None, expiration=None, priority=10, 
            connection=None, auth_token=None, bundle_id=None, topic=None
        ):
        topic = topic or bundle_id or self.bundle_id
        if not topic:
            raise ImproperlyConfigured(
                'You must provide your bundle_id if you do not specify a topic'
            )

        data = {}
        aps_data = {}

        if action_loc_key or loc_key or loc_args:
            alert = {"body": alert} if alert else {}
            if action_loc_key:
                alert["action-loc-key"] = action_loc_key
            if loc_key:
                alert["loc-key"] = loc_key
            if loc_args:
                alert["loc-args"] = loc_args

        if alert is not None:
            aps_data["alert"] = alert

        if badge is not None:
            aps_data["badge"] = badge

        if sound is not None:
            aps_data["sound"] = sound

        if category is not None:
            aps_data["category"] = category

        if content_available:
            aps_data["content-available"] = 1

        if mutable_content:
            aps_data["mutable-content"] = 1

        data["aps"] = aps_data
        data.update(extra)

        print("data:")
        # for key in data:
        #     print("\t"+key+":"+data[key])
        # Convert to json, avoiding unnecessary whitespace with separators (keys sorted for tests)
        json_data = json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")
        print("data:"+json_data)

        if len(json_data) > MAX_NOTIFICATION_SIZE:
            raise PayloadTooLarge("Notification body cannot exceed %i bytes" % (MAX_NOTIFICATION_SIZE))

        # If expiration isn't specified use 1 month from now
        expiration_time = expiration if expiration is not None else int(time.time()) + 2592000

        auth_token = auth_token or self._create_token()

        request_headers = {
            'apns-expiration': str(expiration_time),
            'apns-id': str(identifier or uuid.uuid4()),
            'apns-priority': str(priority),
            'apns-topic': topic,
            'authorization': 'bearer {0}'.format(auth_token)
        }
        print("headers:")
        for key in request_headers:
            print("\t"+key+":"+request_headers[key])
    # apns-id:7cc5837e-2e90-4359-a24f-ba06be5fc9be
	# authorization:bearer eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Iko1N0tEUUpXTE4ifQ.eyJpc3MiOiJYNFoyTDVLTTQzIiwiaWF0IjoxNTk4MTY3OTEyLjI5ODQxNH0.KmYLJFamlCejzEkEaDPGXF4M2v6dUL2KBn0VyV14T-z4-c5cdfZwwkBzNk2vTg7GBqsDMqammkTs0i3f2V3oPQ
	# apns-topic:com.nb.dev9
	# apns-priority:10
	# apns-expiration:1600759912

#eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Iko1N0tEUUpXTE4ifQ
#  atob('eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Iko1N0tEUUpXTE4ifQ');
#    "{"alg":"ES256","typ":"JWT","kid":"J57KDQJWLN"}"
#eyJpc3MiOiJYNFoyTDVLTTQzIiwiaWF0IjoxNTk4MTY3OTEyLjI5ODQxNH0
#atob('eyJpc3MiOiJYNFoyTDVLTTQzIiwiaWF0IjoxNTk4MTY3OTEyLjI5ODQxNH0')
#"{"iss":"X4Z2L5KM43","iat":1598167912.298414}"
#KmYLJFamlCejzEkEaDPGXF4M2v6dUL2KBn0VyV14T-z4-c5cdfZwwkBzNk2vTg7GBqsDMqammkTs0i3f2V3oPQ
# remove 2 hyphens, then atob() returns something.
        print("registration id:"+registration_id)

# data:{"aps":{"alert":"from cmdline, when app iswith jiguang. received APNsID 9:22 running "}}
# headers:
# 	apns-id:0fa145bc-d07a-4366-b199-9270de952880
# 	authorization:bearer eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Iko1N0tEUUpXTE4ifQ.eyJpc3MiOiJYNFoyTDVLTTQzIiwiaWF0IjoxNTk4MTY5OTI3LjE1OTk2Mn0.6E-oyK8_3Bi5vn80CsBHSIPWgYdF0Crf-CpI_Oe5zEjP3DHYzrTmCPVzXu6KYKHCs4HFSYjz3pD6_bnzzSGMtQ
# 	apns-topic:com.nb.dev9
# 	apns-priority:10
# 	apns-expiration:1600761927
# registration id:B12C9FAD68C77B377F4106A1761D31B2892D61D342731A7445FB6B6DA890B197        

        if connection:
            response = self._send_push_request(connection, registration_id, json_data, request_headers)
        else:
            with closing(self._create_connection()) as connection:
                response = self._send_push_request(connection, registration_id, json_data, request_headers)

        return response

    def _send_push_request(self, connection, registration_id, json_data, request_headers):
        connection.request(
            'POST', 
            '/3/device/{0}'.format(registration_id), 
            json_data, 
            headers=request_headers
        )
        response = connection.get_response()

        if response.status != APNSResponse.Success:
            body = json.loads(response.read().decode('utf-8'))
            reason = body.get("reason")

            if reason:
                exceptions_module = importlib.import_module("gobiko.apns.exceptions")
                # get exception class by name
                raise getattr(exceptions_module, reason, InternalException)

        return True

bid="com.nb.yjy133" #"com.nb.yjy128" #"com.nb2.dev9"  #"com.nb.dev9" #
msgtext="from cmdline, "
if (bid=="com.nb.dev9"):
    client = APNsClient(
    team_id="X4Z2L5KM43", #"Y5AQM22QDU", #
    bundle_id="com.nb.dev9",
    auth_key_id="J57KDQJWLN",
    auth_key_filepath="/Users/yogi/Downloads/AuthKey_J57KDQJWLN.p8",
    use_sandbox=False,
    force_proto='h2'
    )
    APNsID="F5DA74B1E7A08E9BE2EB891AEC4C2DA4A79A760A4EE7A8ECBCE56A22D9CEB1A8" #good
    APNsID="7E840B9C44ECE9FFFE32FB5F2842838B86549DDE25FE21F72E35DF72D65A3D05" #bad
    client.send_message(APNsID,msgtext)
elif (bid=="com.nb.yjy128"):
    client = APNsClient(
    team_id="X4Z2L5KM43", #"Y5AQM22QDU", #
    bundle_id="com.nb.yjy128",
    auth_key_id="J57KDQJWLN",
    auth_key_filepath="/Users/yogi/Downloads/AuthKey_J57KDQJWLN.p8",
    use_sandbox=False,
    force_proto='h2'
    )
    APNsID="7E840B9C44ECE9FFFE32FB5F2842838B86549DDE25FE21F72E35DF72D65A3D05" #good
    APNsID="F5DA74B1E7A08E9BE2EB891AEC4C2DA4A79A760A4EE7A8ECBCE56A22D9CEB1A8" #gobiko.apns.exceptions.DeviceTokenNotForTopic
    client.send_message(APNsID,msgtext)
elif (bid=="com.nb2.dev9"):
    client = APNsClient(
    team_id="Y6N4VC6T2C", #"Y5AQM22QDU", #
    bundle_id="com.nb2.dev9",
    auth_key_id="48WST6764Z",
    auth_key_filepath="/Users/yogi/Downloads/AuthKey_48WST6764Z.p8",
    use_sandbox=False,
    force_proto='h2'
    )
    APNsID="D1E728FF48C796FA851E9415DE0170E5C438A9275B6BAD9F2AF29FAEFAF3FC8E" #good
    APNsID="F5DA74B1E7A08E9BE2EB891AEC4C2DA4A79A760A4EE7A8ECBCE56A22D9CEB1A8" #gobiko.apns.exceptions.DeviceTokenNotForTopic
    client.send_message(APNsID,msgtext)
elif (bid=="com.nb.yjy133"):
    client = APNsClient(
    team_id="X4Z2L5KM43", #"Y5AQM22QDU", #
    bundle_id=bid,
    auth_key_id="956TVBK24A",
    auth_key_filepath="/Users/yogi/Downloads/AuthKey_956TVBK24A.p8",
    use_sandbox=False,
    force_proto='h2'
    )
    APNsID="78CE05CF61B71B6AB7154A66A6831D056823E4F654C8E0D59C0BF9ACFB0E63B8" #
    client.send_message(APNsID,msgtext)
else:
    print("bundle id not expected:"+bid)



