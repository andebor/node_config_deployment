# Sesam Node Configuration Deployment

Python script for deploying a given node config zip file to a node instance

**WARNING** This deployment script will replace the entire existing configuration on the target Sesam Node

## Settings
All settings are configured by using environment variables.

**Required settings:**
* NODE_API_URL - Url to Node instance (i.e. https://12345.sesam.cloud/api)
* NODE_JWT - Json web token for user
* NODE_PROJECT_PATH - path to project, default '/project'. Not required if run with Docker.


**Optional settings:**
* NODE_LOGLEVEL - INFO, DEBUG, WARN (default: INFO)
* VSTS_LOGGING - Enable VSTS prefix syntax on logging to get better utilization of the error summary in build logs
* NODE_PATH - For use with Docker. Required if node configuration is not stored on the root level of the deployed directory. 
* NODE_ENV_VARS_FILENAME - Allow you to upload the given json file with environment variables during deployment. 
* NODE_WHITELIST - If provided, the deployment will only contain the files listed in this file.
* NODE_VERIFY_VARS - Boolean, Will verify if the environment variables used in systems and pipes are defined in target node
* NODE_VERIFY_SECRETS - Same as NODE_VERIFY_VARS, but with secrets.


## Run

#### Python
```bash
NODE_API_URL=https://12345.sesam.cloud/api NODE_JWT=hjdakfhja.. NODE_PROJECT_PATH=/Users/john/dev/project python3 deploy.py
```

#### Run with docker

**Requires a volume mapping to *`/project`***

Example:
```bash
docker run --rm -e "NODE_API_URL=https://12345.sesam.cloud" \
    -e "NODE_JWT=$NODE_JWT" \
    -v /Users/john/dev/project/:/project \
    sesam/nodeconfigdeploy
```


Example of expected directory structure (including optional files)
```
my_repo
 |-node (requires NODE_PATH=node)
    |- systems
    |    |- my_system.conf.json 
    |- pipes
    |    |- my_pipe.conf.json
    |- variables
    |    |- variables-test.json
    |- deployment
    |    |- whitelist-prod.txt
```