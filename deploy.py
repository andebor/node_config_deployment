#!/usr/bin/env python

import io
import json
import logging
import os
import tempfile

import re
import requests
import sys
import zipfile
from collections import defaultdict


def str_to_bool(string_input):
    return str(string_input).lower() == "true"

vsts_logging = str_to_bool(os.getenv('VSTS_LOGGING', False))


class VSTSformatter(logging.Formatter):
    """Log formatter for VSTS to populate build summary page"""
    error_format = '##vso[task.logissue type=error;]%(message)s'
    warning_format = '##vso[task.logissue type=warning;]%(message)s'
    debug_format = '##[debug]%(message)s'
    default_format = '%(message)s'

    def format(self, record):
        if record.levelno == logging.ERROR:
            return logging.Formatter(self.error_format).format(record)
        elif record.levelno == logging.WARNING:
            return logging.Formatter(self.warning_format).format(record)
        elif record.levelno == logging.DEBUG:
            return logging.Formatter(self.debug_format).format(record)
        return logging.Formatter(self.default_format).format(record)

# Define logging
format_string = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
if vsts_logging:
    formatter = VSTSformatter()
else:
    formatter = logging.Formatter(format_string)
logger = logging.getLogger('SesamNodeDeploy')
stdout_handler = logging.StreamHandler()
stdout_handler.setFormatter(formatter)
logger.addHandler(stdout_handler)

loglevel = os.getenv("NODE_LOGLEVEL", "DEBUG")
logger.setLevel({"INFO": logging.INFO, "DEBUG": logging.DEBUG, "WARN": logging.WARNING,
                 "ERROR": logging.ERROR}.get(loglevel))

# expected path for repo with predefined directory structure
project_root = os.getenv('NODE_PROJECT_PATH', "/project")


def failed_exit():
    if vsts_logging:
        logger.info("##vso[task.complete result=Failed;]DONE")
        sys.exit(0)
    else:
        sys.exit(1)


class ApiConnector(object):
    """Connector class for Node service API"""

    def __init__(self, base_url, jwt):
        """Initialise instance with base url and jwt"""
        self.api_base_url = base_url
        self.jwt = jwt
        self.headers = {
            'AUTHORIZATION': 'bearer {}'.format(self.jwt),
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        self.session = requests.session()
        self.session.headers.update(self.headers)

    def check_api_health(self):
        """Check if API endpoint is up and healthy"""
        health_url = "{}/health".format(self.api_base_url)
        try:
            logger.debug("Checking api health.")
            health_resp = self.session.get(health_url)
        except Exception:
            logger.exception("Exception while trying to check API health. Aborting.")
            failed_exit()

        if health_resp.status_code != 200:
            logger.error("API health check did not return 200. Aborting.")
            failed_exit()
        logger.info("API is healthy")

    def upload_json_config(self, config, payload_type="zip"):
        """Upload zip file to configuration endpoint"""
        config_url = "{}/config".format(self.api_base_url)

        files = {'config.zip': config}
        headers = self.headers
        if payload_type == "zip":
            headers['Content-Type'] = 'application/zip'
        try:
            if payload_type == "zip":
                logger.info("Uploading zip configuration to API endpoint.")
                config_resp = self.session.put(config_url, files=files, headers=headers)
            else:
                logger.info("Uploading json configuration to API endpoint.")
                config_resp = self.session.put(config_url, json=config, headers=headers)
        except Exception:
            logger.exception("Exception during configuration PUT operation. Aborting deployment.")
            failed_exit()

        errors = []
        warnings = []
        try:
            config_errors = config_resp.json().get('validation_errors', list())
            for error in config_errors:
                for element in error['config-errors']:
                    if element['level'] == "warning":
                        warnings.append("{} - {}".format(element['msg'], error['posted-config']['_id']))
                    else:
                        errors.append("{} - {}".format(element['msg'], error['posted-config']['_id']))
        except json.JSONDecodeError as e:
            pass

        if len(errors) > 0:
            for error in errors:
                logger.error(error)
        if len(warnings) > 0:
            for warning in warnings:
                logger.warning(warning)

        if config_resp.status_code != 200:
            logger.error("Configuration upload did not return 200. See listed errors. \nFull response: \n{}"
                         .format(config_resp.text))
            failed_exit()
        else:
            logger.info("Successfully uploaded configuration.")
            logger.info("Full response: \n{}".format(config_resp.text))

    def get_env_variables(self):
        """Get all environment variables for Node instance"""
        var_url = "{}/env".format(self.api_base_url)

        try:
            logger.debug("Retrieving environment variables from API endpoint")
            resp = self.session.get(var_url)
        except Exception:
            logger.exception("Failed to get environment variables. Aborting")
            failed_exit()
        if resp.status_code != 200:
            logger.error("Failed to get environment variables. Endpoint returned status code {}"
                         .format(resp.status_code))
            failed_exit()
        return resp.json()

    def get_secrets(self):
        """Get all secret keys for Node instance"""
        secret_url = "{}/secrets".format(self.api_base_url)
        try:
            logger.debug("Retrieving secrets from API endpoint")
            resp = self.session.get(secret_url)
        except Exception:
            logger.exception("Failed to get secrets. Aborting")
            failed_exit()
        if resp.status_code != 200:
            logger.error("Failed to get secrets. Endpoint returned status code {}.\nFull response: {}"
                         .format(resp.status_code, resp.text))
            failed_exit()
        return resp.json()

    def get_env_variable_keys(self):
        return list(self.get_env_variables().keys())

    def post_env_variables_list(self, variables):
        """Post new environment variables list on Node instance"""
        var_url = "{}/env".format(self.api_base_url)

        try:
            logger.info("Posting env variables to remote node instance")
            resp = self.session.post(var_url, json=variables)
        except Exception:
            logger.exception("Failed to post environment variables")
            failed_exit()
        if resp.status_code != 200:
            logger.error("Failed to post variables. Endpoint returned status code {}"
                         .format(resp.status_code))
            failed_exit()


def get_stored_env_variables(path, filename):
    """Get dict of environment variables stored in file"""
    env_file = "{}/variables/{}".format(path, filename)
    if os.path.isfile(env_file):
        with open(env_file, 'r') as f:
            env_vars = json.loads(f.read())
        if len(env_vars) > 0:
            return env_vars
        return dict()
    else:
        logger.error("Environment variables file not found on path {}".format(env_file))
        failed_exit()


def get_stored_env_variables_keys(path, filename):
    """Get list of environment variables stored in file"""
    env_vars = get_stored_env_variables(path, filename)
    if len(env_vars) > 0:
        return list(env_vars.keys())
    return list()


def get_stored_secrets(path):
    """Get list of secrets stored in file"""
    secrets_file = "{}/secrets.json".format(path)
    if os.path.isfile(secrets_file):
        with open(secrets_file, 'r') as f:
            secrets = json.loads(f.read())
        return secrets
    else:
        logger.error("Secrets file not found. Expects 'secrets.json' inside Node directory")
        failed_exit()


def validate_list(reference_list, check_list):
    """Check if all entries in reference_list exist in the check_list"""
    missing_entries = []
    for entry in reference_list:
        if entry not in check_list:
            missing_entries.append(entry)
    return missing_entries


def load_json(json_file):
    """Load json data"""
    if os.path.isfile(json_file):
        with open(json_file, 'r') as f:
            config = json.loads(f.read())
        return config
    else:
        logger.error("Json file not found on given path")
        failed_exit()


def load_whitelist(base_path, filename):
    """Get list of whitelisted files to use in zip file"""
    file_path = "{}/deployment/{}".format(base_path, filename)
    if os.path.isfile(file_path):
        with open(file_path, 'r') as f:
            files = f.read().splitlines()
        if len(files) > 0:
            whitelist = defaultdict()
            for file in files:
                parts = file.split('/')
                if len(parts) > 1:
                    if parts[0] in whitelist:
                        whitelist[parts[0]].append(parts[1])
                    else:
                        whitelist[parts[0]] = [parts[1]]
                else:
                    if 'root' in whitelist:
                        whitelist['root'].append(parts[0])
                    else:
                        whitelist['root'] = [parts[0]]
            return whitelist
    else:
        logger.error("Whitelist file not found on path {}".format(file_path))
        failed_exit()


def get_files_to_deploy(directory, whitelist=None):
    """
    Create a list of tuples with filename and relative paths based on files listed in whitelist file.
    If no whitelist is provided only the files under systems and pipes directories
    will be added to the list
    """

    default = {
        "pipes": [
            "*"
        ],
        "systems": [
            "*"
        ],
        "root": [
            "node-metadata.conf.json"
        ]
    }

    if not whitelist:
        whitelist = default

    for folder in whitelist.keys():
        if folder != "root":
            if not os.path.isdir(os.path.join(directory, folder)):
                logger.error("Can't find {} directory in given directory".format(folder))
                failed_exit()

    files_to_deploy = list()

    for folder in whitelist.keys():
        if folder != "root":
            for base, dirs, files in os.walk(os.path.join(directory, folder)):
                for file in files:
                    if file in whitelist[folder] or '*' in whitelist[folder]:
                        fn = os.path.join(base, file)
                        files_to_deploy.append((fn, os.path.relpath(fn, directory)))

    if 'root' in whitelist:
        for base, dirs, files in os.walk(directory):
            for file in files:
                if file in whitelist['root'] or '*' in whitelist['root']:
                    fn = os.path.join(directory, file)
                    if os.path.isfile(fn):
                        files_to_deploy.append((fn, os.path.relpath(fn, directory)))
    return files_to_deploy


def create_zip(payload, payload_type):
    """Create zip based on a list of tuples containing (absolute file path, zip relative path)"""

    tf = tempfile.TemporaryFile(suffix='.zip')
    zf = zipfile.ZipFile(tf, mode='w', compression=zipfile.ZIP_BZIP2)

    if payload_type == 'filelist':
        for fn, relpath in payload:
            zf.write(fn, relpath)
    elif payload_type == 'json_array':
        for config in payload:
            zf.writestr("{}.conf.json".format(config['_id'].lower()), json.dumps(config))
    else:
        logger.error("Unknown payload type. Aborting")
        failed_exit()

    zf.close()
    tf.seek(0)
    return tf.read()


def get_disabled_dummy_pipe(pipe_id):
    """Create a disabled dummy pipe with the given pipe ID"""

    template = {
        "_id": "{}".format(pipe_id),
        "type": "pipe",
        "source": {
            "type": "embedded"
        },
        "pump": {
            "mode": "off"
        }
    }

    return template


def _find_dict_value(value, search_dict):
    """Search for value in a dictionary"""
    if hasattr(search_dict, 'items'):
        for k, v in search_dict.items():
            if isinstance(v, str) and value in v:
                yield v
            if isinstance(v, dict):
                for result in _find_dict_value(value, v):
                    yield result
            elif isinstance(v, list):
                for d in v:
                    for result in _find_dict_value(value, d):
                        yield result


def find_env_vars_in_dict(search_dict):
    """Get all Sesam env vars defined in dict values"""
    results = _find_dict_value("$ENV(", search_dict)
    found_vars = list()
    for result in results:
        match_list = re.findall(r'\$ENV\((.+?)\)', result)
        if match_list:
            for match in match_list:
                if match not in found_vars:
                    found_vars.append(match)
    return found_vars


def find_secrets_in_dict(search_dict):
    """Get all Sesam secrets defined in dict values"""
    results = _find_dict_value("$SECRET", search_dict)
    found_secrets = list()
    for result in results:
        match_list = re.findall(r'\$SECRET\((.+?)\)', result)
        if match_list:
            for match in match_list:
                if match not in found_secrets:
                    found_secrets.append(match)
    return found_secrets


def disable_pump_scheduler(config_array):
    """Modify node config to disable task scheduler"""
    config_exists = False
    for config in config_array:
        if config['_id'] == "node":
            if 'task_manager' in config:
                config['task_manager']['disable_pump_scheduler'] = True
            else:
                config['task_manager'] = {"disable_pump_scheduler": True}
            config_exists = True

    default = {
        "_id": "node",
        "type": "metadata",
        "task_manager": {
            "disable_pump_scheduler": True
        }
    }

    if not config_exists:
        config_array.append(default)

    return config_array


def get_config_as_array(files_to_deploy):
    """Returns an array with the full node config based on the list of tuples provided"""
    config_array = []

    for filename, relpath in files_to_deploy:
        config_array.append(load_json(filename))

    return config_array


def main():

    api_url = os.getenv('NODE_API_URL')
    if not api_url:
        logger.error("Missing 'NODE_API_URL' environment variable. Aborting.")
        failed_exit()

    node_jwt = os.getenv('NODE_JWT')
    if not node_jwt:
        logger.error("Missing 'NODE_JWT' environment variable. Aborting.")
        failed_exit()

    node_path = os.getenv('NODE_PATH')
    if not node_path:
        logger.warning("No 'NODE_PATH' environment variable found. Assuming git root directory.")
        base_path = project_root
    else:
        base_path = os.path.join(project_root, node_path)

    connect = ApiConnector(api_url, node_jwt)
    connect.check_api_health()

    env_vars_filename = os.getenv('NODE_ENV_VARS_FILENAME', False)

    if env_vars_filename:
        logger.info("Uploading environment variables from {}".format(env_vars_filename))
        local_env_vars = get_stored_env_variables(base_path, env_vars_filename)
        if len(local_env_vars) > 0:
            connect.post_env_variables_list(local_env_vars)

    # Get deployment whitelist
    whitelist_filename = os.getenv("NODE_WHITELIST", None)
    if whitelist_filename:
        whitelist = load_whitelist(base_path, whitelist_filename)
        logger.debug("Using whitelist: {}".format(whitelist))
    else:
        whitelist = None
        logger.debug("Creating zip without whitelist")

    disable_on_upload = str_to_bool(os.getenv("NODE_DISABLE_PUMP_SCHEDULER", False))
    if disable_on_upload:
        # check if node metadata file is in whitelist
        if whitelist:
            if 'root' in whitelist:
                if not "node-metadata.conf.json" in whitelist['root']:
                    whitelist['root'].append("node-metadata.conf.json")
            else:
                whitelist['root'] = ["node-metadata.conf.json"]

        files_to_deploy = get_files_to_deploy(base_path, whitelist)
        config_array = get_config_as_array(files_to_deploy)

        # add 'disable_pump_scheduler' to node metadata
        config_array = disable_pump_scheduler(config_array)
    else:
        files_to_deploy = get_files_to_deploy(base_path, whitelist)
        config_array = get_config_as_array(files_to_deploy)

    zip = create_zip(config_array, payload_type='json_array')

    # check if necessary variables
    verify_env_vars = str_to_bool(os.getenv("NODE_VERIFY_VARS", False))
    verify_secrets = str_to_bool(os.getenv("NODE_VERIFY_SECRETS", False))

    if verify_env_vars or verify_secrets:
        all_used_vars = list()
        all_used_secrets = list()
        for fn, relpath in files_to_deploy:
            config = load_json(fn)

            if verify_env_vars:
                env_vars = find_env_vars_in_dict(config)
                for env_var in env_vars:
                    if env_var not in all_used_vars:
                        all_used_vars.append(env_var)

            if verify_secrets:
                secrets = find_secrets_in_dict(config)
                for secret in secrets:
                    if secret not in all_used_secrets:
                        all_used_secrets.append(secret)

        logger.debug("All environment variables used by pipes and systems in configuration:\n{}".format(all_used_vars))
        logger.debug("All secrets used by pipes and systems in configuration:\n{}".format(all_used_secrets))
        failed_verification = False

        if verify_env_vars:
            logger.debug("Comparing used env vars with remote env vars.")
            missing_vars = list()
            remote_vars = connect.get_env_variable_keys()
            for var in all_used_vars:
                if var not in remote_vars:
                    missing_vars.append(var)
            if len(missing_vars) > 0:
                logger.error("Missing environment variables! The following env vars "
                             "are used in the configuration, but not deployed to the node: {}"
                             .format(missing_vars))
                failed_verification = True
            else:
                logger.info("All necessary env variables present on remote server.")

        if verify_secrets:
            logger.debug("Comparing used secrets with remote secrets.")
            missing_secrets = list()
            remote_secrets = connect.get_secrets()
            for secret in all_used_secrets:
                if secret not in remote_secrets:
                    missing_secrets.append(secret)
            if len(missing_secrets) > 0:
                logger.error("Missing secrets! The following secrets are used "
                             "in the configuration, but not deployed to the node: {}"
                             .format(missing_secrets))
                failed_verification = True
            else:
                logger.info("All necessary secrets present on remote server.")

        if failed_verification:
            failed_exit()

    # Deploy config
    connect.upload_json_config(zip)


if __name__ == '__main__':
    main()
