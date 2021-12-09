import logging
import logging.config 
import time
import yaml
from envyaml import EnvYAML
import os
import json
import string
import asyncio
import subprocess
from gql import gql, Client
from gql.transport.aiohttp import AIOHTTPTransport
import authenticate as auth
import subscribe as sub

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
    
    jwt = auth.authenticate(config["gql"]["address"], user, password, 'profileTags: ["app profile", "application", "http_bridge"]')
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
        jwt = auth.authenticate(config["gql"]["address"], user, password, 'profileTags: ["app profile", "application", "http_bridge"]')
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
    
    # GQL
    jwt_init = os.environ["JWT_ENV_"+application.upper()]
    transport_init = AIOHTTPTransport(url="http://{}/graphql".format(gql_address), headers={'Authorization': 'Bearer ' + jwt_init})
    client_init = Client(transport=transport_init, fetch_schema_from_transport=False)
    
    query_uuid = gql(
        """
        query GetHttpBridgeObjectId {
            getUserProfileId
        }
        """
    )
    query_uuid_result = await client_init.execute_async(query_uuid)
    
    while True:
        await asyncio.sleep(status_timeout)
        try:
            jwt = os.environ["JWT_ENV_"+application.upper()]
            transport = AIOHTTPTransport(url="http://{}/graphql".format(gql_address), headers={'Authorization': 'Bearer ' + jwt})
            client = Client(transport=transport, fetch_schema_from_transport=False)
            # Get the uuid of the dispatcher worker object
            # query_uuid = gql(
            # """
            # query GetHttpBridgeObjectId {
            #     getUserProfileId
            # }
            # """
            # )
            # query_uuid_result = await client.execute_async(query_uuid)
            
            #logger.debug(query_uuid_result)
            
            if query_uuid_result['getUserProfileId'] == None:
                logger.debug("Http Bridge object not found")
                continue
        
            #uuid = query_uuid_result['objects'][0]['id']
            uuid = query_uuid_result['getUserProfileId']
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
        except Exception as e:
            logger.error(e)
            os._exit(-1)
            #sys.exit(1)
            #os.kill(os.getpid(), signal.SIGINT)
    return 0

async def init_app():
    os.system('python ./http-bridge/http-bridge.py ')

if __name__ == "__main__":
    # Async events loop
    loop = asyncio.get_event_loop()
    # TODO: In the next version of the bridge get jwt from the user HTTP requests
    # Take care of gql credentials
    user = config["gql"]["username"]
    password = config["gql"]["password"]
    # Authenticate
    logger.info("Initialize GraphQL access token.")
    jwt_env_key = init_jwt_environment(config["gql"]["address"], "httpbridge", user, password)
    token_id = auth.get_token_id(config["gql"]["address"], jwt_env_key)
    #
    subprocess.Popen(["python", "./http-bridge/http-bridge.py"])
    # Create authenticate refresh process
    logger.info("Start auto refresh process of GraphQL access token")
    loop.create_task(refresh_jwt_environment(config["gql"]["address"], "httpbridge", user, password, config["gql"]["refresh_token_timeout"]))
    # Start is alive status process
    logger.info("Start http bridge is alive process.")
    loop.create_task(alive_status(config["gql"]["address"], "httpbridge", config["processes"]["is_alive_timeout"]))
    # Start the http bridge
    #loop.create_task(init_app())
    # Start subscriptions
    loop.create_task(sub.subscribe(config["gql"]["address"], jwt_env_key, "controls"+":"+token_id))
    # Loop runs until the bridge is killed
    loop.run_forever()
    

