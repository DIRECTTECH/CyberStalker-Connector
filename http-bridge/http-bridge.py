import logging
import logging.config 
import time
import yaml
from envyaml import EnvYAML
import os
import json
import string
import asyncio
from flask import Flask, request, jsonify, abort
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
from gql import gql, Client
from gql.transport.aiohttp import AIOHTTPTransport
import authenticate as auth
import regex

# EnvYAML necessary to parse environment vairables for the configuration file
config = EnvYAML("./docs/conf.yaml") 
# Logging
logging.config.dictConfig(config["logging"])
logger = logging.getLogger("bridge")

def init_jwt_environment(gql_address, application, user, password):
    """Initialise the JWT access token for an application.

        The access token is placed in an environment variable representing a dictionnary
        with keys of the form JWT_ENV_{NAME OF APPLICATION FROM CONFIG} and values the
        access tokens.

        Parameters
        ----------
        gql_address : str
            GraphQL API URL
            
        application : str
            Name of the application as per the configuration file.
            
        user : str
            Username of the application.
            
        password : str
            Password of the application.
            
        Returns
        -------
        JWT env key : str
            Key used to retrieve the active JWT from the environment variables. 
            Format JWT_ENV_{NAME OF APPLICATION FROM CONFIG}.
    """
    
    jwt = auth.authenticate(config["gql"]["address"], user, password)
    try:
        # Check if the key is already in the environment
        jwt_env = os.environ["JWT_ENV_"+application.upper()]
    except:
        # If not create it
        with open(os.path.expanduser("~/.bashrc"), "a") as outfile:
            outfile.write("export {}={}".format("JWT_ENV_"+application.upper(), jwt))
        #
        os.environ["JWT_ENV_"+application.upper()] = jwt
        jwt_env = os.environ["JWT_ENV_"+application.upper()]
    return "JWT_ENV_"+application.upper()
    
async def refresh_jwt_environment(gql_address, application, user, password, timeout):
    """Refresh the access token for an application at regular time intervals.

        Runs as a periodic task in the async loop.

        Parameters
        ----------
        gql_address : str
            GraphQL API URL
            
        application : str
            Name of the application as per the configuration file.
            
        user : str
            Username of the application.
            
        password : str
            Password of the application.
            
        timeout : int
            In seconds, how long until the refresh must happen.
    """
    
    while True:
        await asyncio.sleep(timeout)
        jwt = auth.authenticate(config["gql"]["address"], user, password)
        try:
            jwt_env = os.environ["JWT_ENV_"+application.upper()]
        except:
            #
            with open(os.path.expanduser("~/.bashrc"), "a") as outfile:
                outfile.write("export {}={}".format("JWT_ENV_"+application.upper(), jwt))
            #
            os.environ["JWT_ENV_"+application.upper()] = jwt
            jwt_env = os.environ["JWT_ENV_"+application.upper()]
    return 0

def current_milli_time():
    return round(time.time() * 1000)

async def alive_status(gql_address, application, status_timeout):
    """Send the alive status message for the http bridge module

        Runs as a periodic task in the async loop.

        Parameters
        ----------
        gql_address : str
            GraphQL API URL
            
        application : str
            Name of the application.
            
        status_timeout : int
            How often the alive status will be sent in seconds.
    """
    while True:
        await asyncio.sleep(status_timeout)
        jwt = os.environ["JWT_ENV_"+application.upper()]
        transport = AIOHTTPTransport(url="http://{}/graphql".format(gql_address), headers={'Authorization': 'Bearer ' + jwt})
        client = Client(transport=transport, fetch_schema_from_transport=False)
        # Get the uuid of the dispatcher worker object
        query_uuid = gql(
            """
            query GetDispatcherWorkerId {
            objects(filter: {
                name: {
                    equalTo: "Http_Bridge"
                }
                schemaType: {
                    equalTo: "application"
                }
            }){
                id
            }
            }
            """
        )
        query_uuid_result = await client.execute_async(query_uuid)
        
        logger.debug(query_uuid_result)
        
        if len(query_uuid_result['objects']) == 0:
            logger.debug("Http Bridge object not found")
            continue
        
        uuid = query_uuid_result['objects'][0]['id']
        # Send the alive message
        optionsArrayPayload = "[{ groupName: \"HealthCheck\", property: \"Message\", value: \"Http Bridge is alive.\"}]"
        mutation_alive_status = gql(
            """
            mutation HttpBirdgeIsAlive {{
            updateObjectPropertiesByName(input: {{
                objectId: "{}"
                transactionId: "{}"
                propertiesArray: {}
                }}){{
                    boolean
                }}
            }}
            """.format(uuid, current_milli_time(), optionsArrayPayload)
        )
        mutation_alive_status_result = await client.execute_async(mutation_alive_status)
        #logger.debug(mutation_alive_status_result)
        #logger.debug("Http Bridge is alive status updated.")
    return 0

app = Flask(__name__)
httpauth = HTTPBasicAuth()

@httpauth.verify_password
def verify_password(username, password):
    if username == config["auth"]["username"] and password == config["auth"]["password"]:#check_password_hash(config["auth"]["password"], password):
        return username

@app.errorhandler(404)
def not_found(e):
    return jsonify(error=str(e)), 404

@app.errorhandler(403)
def forbidden(e):
    return jsonify(error=str(e)), 401

@app.errorhandler(401)
def unauthorised(e):
    return jsonify(error=str(e)), 401

@app.errorhandler(500)
def internal(e):
    return jsonify(error=str(e)), 500

@app.errorhandler(501)
def notimplemented(e):
    return jsonify(error=str(e)), 501

@app.route('/')
def get_info():
    return 'This is the Pixel Core HTTP bridge.'

@app.route('/<uuid>/properties', methods=["POST"])
@httpauth.login_required
def update_properties(uuid):
    imput_json = request.get_json(force=True)
       
    update_results = []
    for update in imput_json:
        # Build the update payload
        payload = []
        for k, v in update.items():
            f = k.split('/')
            groupname = f[0]
            prop = f[1]
            payload.append({'groupName': groupname,'property': prop,'value': v})
        # Format payload for GQL 
        # regex.sub(r'(?<=, |{)"(.*?)"(?=: )', r'\1', jsonSchema)
        payload = json.dumps(payload).replace("'","\"")
        #logger.info(payload)
        optionsArrayPayload = "{}".format(payload)#"[{ \\\"groupname\\\": \\\"Measurements\\\",\\\"property\\\":\\\"CURRENT_RELATIVE_HUMIDITY\\\",\\\"value\\\": \\\"100\\\"}]"
        optionsArrayPayload = regex.sub(r'(?<=, |{)"(.*?)"(?=: )', r'\1', optionsArrayPayload)
        
        # TODO: Wrap all that in a function
        gql_address = config["gql"]["address"]
        jwt = os.environ["JWT_ENV_HTTPBRIDGE"]
        
        transport = AIOHTTPTransport(url="http://{}/graphql".format(gql_address), headers={'Authorization': 'Bearer ' + jwt})
        client = Client(transport=transport, fetch_schema_from_transport=False)
        update_object_properties_mutation = gql(
            """
            mutation {{
                updateObjectPropertiesByName(input: {{
                    objectId: "{}"
                    transactionId: "{}"
                    propertiesArray: {}
                    }}){{
                        boolean
                    }}
                }}
        """.format(uuid, current_milli_time(), optionsArrayPayload)
        )
        result = client.execute(update_object_properties_mutation)
        
        logging.debug(result)
        
        update_results.append(result)
    
    if all(r['updateObjectPropertiesByName']['boolean'] == True for r in update_results): #result['updateObjectProperties']['boolean']:
        return 'Update successful.'
    elif result['updateObjectPropertiesByName']['boolean'] is None:
        abort(500, description="GraphQL error: {}".format(update_results))
    else:
        abort(403, description="Forbidden")
    
    return 0

@app.route('/<uuid>/control', methods=["POST"])
@httpauth.login_required
def rpc(uuid):
    input_json = request.get_json(force=True) 
    
    logger.debug(input_json)
    
    rpc_name = input_json["rpc"]
    rpc_params = "{}".format(json.dumps(input_json["params"]))#.replace('"',"\\\""))
    rpc_params = regex.sub(r'(?<=, |{)"(.*?)"(?=: )', r'\1', rpc_params)
    
    rpc_timeout = int(config['rpc']['timeout'])
    if "timeout" in input_json.keys():
        rpc_timeout = int(input_json["timeout"])
        if rpc_timeout < 0:
            rpc_timeout = int(config['rpc']['timeout'])
        
    logger.debug("RPC: {}, Params: {}".format(rpc_name, rpc_params))
    
    # TODO: Wrap all that in a function
    gql_address = config["gql"]["address"]
    jwt = os.environ["JWT_ENV_HTTPBRIDGE"]
    
    transport = AIOHTTPTransport(url="http://{}/graphql".format(gql_address), headers={'Authorization': 'Bearer ' + jwt})
    client = Client(transport=transport, fetch_schema_from_transport=False)
    create_rpc_mutation = gql(
        """
        mutation {{
            createControlExecution(input: {{
                controlExecution: {{
                objectId: "{}"
                name: "{}"
                params: {}
                }}
            }}){{
                controlExecution {{
                id
                callerId
                controller
                objectId
                }}
            }}
        }}
    """.format(uuid, rpc_name, rpc_params)
    )
    result = client.execute(create_rpc_mutation)
    
    logging.debug(result)
    
    if result['createControlExecution']['controlExecution']['objectId'] == uuid:
        #return 'RPC initiated.'
        rpc_status = "Initiated"
        rpc_start = time.time()
        rpc_response = "Unknown error"
        while not (rpc_status == "Done" or rpc_status == "Timeout"):
            time.sleep(1)
            query_check_rpc_status = gql(
            """
            query RpcStatus{{
                controlExecutions(filter: {{
                    id: {{
                        equalTo: {}
                    }}
                }}){{
                    nodeId
                    id
                    objectId
                    controller
                    createdAt
                    type
                    name
                    params
                    ack
                    done
                    error
                    linkedControlId
                    callerId
                }}
            }}
            """.format(result['createControlExecution']['controlExecution']['id'])
            )
            check_rpc_status_result = client.execute(query_check_rpc_status)
            
            logger.debug(check_rpc_status_result)
            
            if check_rpc_status_result['controlExecutions'][-1]['done'] == True:
                rpc_status = "Done"
                rpc_response = "RPC completed without genereting reports"
            elif time.time() - rpc_start > rpc_timeout:
                rpc_status = "Timeout"
                rpc_response = "RPC timed out without generating report"
            
        query_rpc_reports = gql(
        """
        query RpcReports{{
            controlExecutions(filter: {{
                linkedControlId: {{
                    equalTo: "{}"
                }}
            }}){{
                nodeId
                id
                objectId
                controller
                createdAt
                type
                name
                params
                ack
                done
                error
                linkedControlId
                callerId
            }}
        }}
        """.format(result['createControlExecution']['controlExecution']['id'])
        )
        rpc_reports_result = client.execute(query_rpc_reports)
        
        logging.debug(rpc_reports_result)
        
        if len(rpc_reports_result['controlExecutions']) == 0:
            return rpc_response
        else:
            return rpc_reports_result
            
    elif result['createControlExecution']['controlExecution']['objectId'] is None:
        abort(404, description="RPC not found")
    else:
        abort(403, description="Forbidden")
    
    return 0

@app.route('/<uuid>/control/stealth', methods=["POST"])
@httpauth.login_required
def stealth_rpc(uuid):
    input_json = request.get_json(force=True) 
    
    logger.debug(input_json)
    
    rpc_name = input_json["rpc"]
    rpc_params = "{}".format(json.dumps(input_json["params"]))#.replace('"',"\\\""))
    rpc_params = regex.sub(r'(?<=, |{)"(.*?)"(?=: )', r'\1', rpc_params)
    
    logger.debug("RPC: {}, Params: {}".format(rpc_name, rpc_params))
    
    # TODO: Wrap all that in a function
    gql_address = config["gql"]["address"]
    jwt = os.environ["JWT_ENV_HTTPBRIDGE"]
    
    transport = AIOHTTPTransport(url="http://{}/graphql".format(gql_address), headers={'Authorization': 'Bearer ' + jwt})
    client = Client(transport=transport, fetch_schema_from_transport=False)
    create_stealth_rpc_mutation = gql(
        """
        mutation {{
            createControlExecutionStealth(input: {{
                objectId: "{}"
                name: "{}"
                params: {}
            }}){{
                boolean
            }}
        }}
    """.format(uuid, rpc_name, rpc_params)
    )
    result = client.execute(create_stealth_rpc_mutation)
    
    logging.debug(result)
    
    if result['createControlExecutionStealth']['boolean']:
        return 'RPC initiated.'
    elif result['createControlExecutionStealth']['boolean'] is None:
        abort(404, description="RPC not found")
    else:
        abort(403, description="Forbidden")
    
    return 0

@app.route('/applications', methods=["GET"])
@httpauth.login_required
def get_applications():
    # TODO: Wrap all that in a function
    gql_address = config["gql"]["address"]
    jwt = os.environ["JWT_ENV_HTTPBRIDGE"]
    
    transport = AIOHTTPTransport(url="http://{}/graphql".format(gql_address), headers={'Authorization': 'Bearer ' + jwt})
    client = Client(transport=transport, fetch_schema_from_transport=False)
    query_applications = gql(
        """
        query GetApplications {
            objects(filter: {
                schemaType: {
                    equalTo: "application"
                }
                }){
                    id
                    name
        schema {
        applicationOwner
        userByBy {
            login
        }
                }
                status:property(propertyName:"HealthCheck/Status")
                }
                }
        """
    )
    result = client.execute(query_applications)
    
    logging.debug(result)
    
    output = ""
    for a in result['objects']:
        uuid = a['id']
        login = a['schema']['userByBy']['login']
        status = a['status']
        if status == True:
            status = "online"
        else:
            continue#status = "offline"
        output = output + uuid + "\t" + login + "\t" + status + "\n"
    
    return output

if __name__ == "__main__":
    # Async events loop
    #loop = asyncio.get_event_loop()
    # TODO: In the next version of the bridge get jwt from the user HTTP requests
    # Take care of gql credentials
    #user = config["gql"]["username"]
    #password = config["gql"]["password"]
    # Authenticate
    #logger.info("Initialize GraphQL access token.")
    #jwt_env_key = init_jwt_environment(config["gql"]["address"], "httpbridge", user, password)
    # Create authenticate refresh process
    #logger.info("Start auto refresh process of GraphQL access token")
    #loop.create_task(refresh_jwt_environment(config["gql"]["address"], "httpbridge", user, password, config["gql"]["refresh_token_timeout"]))
    # Start is alive status process
    #logger.info("Start http bridge is alive process.")
    #loop.create_task(alive_status(config["gql"]["address"], "httpbridge", config["processes"]["is_alive_timeout"]))
    # Start the http-bridge
    #app.run(host='0.0.0.0', port=5060)
    # Loop runs until the bridge is killed
    #loop.run_forever()
    from waitress import serve
    serve(app, host='0.0.0.0', port=5060)

