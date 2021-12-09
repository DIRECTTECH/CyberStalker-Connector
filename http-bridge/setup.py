import logging
import logging.config 
import glob
import string
import yaml
from envyaml import EnvYAML
import json
import asyncio
from gql import gql, Client
from gql.transport.aiohttp import AIOHTTPTransport
import authenticate as auth

# Load dispatcher config
# EnvYAML necessary to parse environment vairables for the configuration file
config = EnvYAML("./docs/conf.yaml")
# Logging
logging.config.dictConfig(config["logging"])
logger = logging.getLogger("setup")
    
def setup_httpbridge_module(config):
    """Setup / sync the schemas and objects for the admin module

        The user management module relies on the existence of a set of schemas and objects
        with fixed uuids provisioned in the platform. This function makes sure those objects
        are there and creates them if necessary.

        Parameters
        ----------
        config : json
            Configuration file for the dispatcher.
    """
    
    # 1. Use the configuration file to access GraphQL as the application
    jwt = auth.authenticate(config['gql']['address'], config['gql']['username'], config['gql']['password'], "")
    transport = AIOHTTPTransport(url="http://{}/graphql".format(config['gql']['address']), headers={'Authorization': 'Bearer ' + jwt})
    client = Client(transport=transport, fetch_schema_from_transport=False)
    
    # 2. Go through the schemas in the module schemas folder
    schemas = glob.glob("./docs/schemas/*.yaml")
    for schema in schemas:
        #logger.setup("Processing schema {}".format(schema))
        with open(schema, 'r') as stream:
            schema_template = yaml.safe_load(stream)
            jsonSchema = "{}".format(json.dumps(schema_template).replace('"',"\\\""))
            query_import_schema = gql(
                """
                mutation {{
                    importSchema(input: {{
                        jsonSchema: "{}"
                        
                    }}) {{
                        uuid
                    }}
                }}
                """.format(jsonSchema)
            )
            result_import_schema = client.execute(query_import_schema)
        
    # 3. Go through the objects in the module objects folder
    objects = glob.glob("./docs/objects/*.yaml")
    for obj in objects:
        uuid = obj.split("/")[-1].split(".")[0]
        query_object = gql(
            """
            query {{
                object(id: "{}"){{
                    id
                }}
            }}
            """.format(uuid)
        )
        result = client.execute(query_object)
        if result['object'] == None:
            with open(obj, 'r') as stream:
                object_template = yaml.safe_load(stream)
            query_create_object =  gql(
                """
                query {{
                    object(id: "{}"){{
                        id
                    }}
                }}
                """.format(uuid)
            )
            with open(obj, 'r') as stream:
                object_template = yaml.safe_load(stream)
            query_create_object = gql(
                """
                mutation cObj {{
                    createObject(input: {{
                        object: {{
                        id: "{}"
                        name: "{}"
                        enabled: true
                        description: "{}"
                        editorgroup: "{}"
                        usergroup: "{}"
                        readergroup: "{}"
                        schemaId: "{}"
                        tags: {}
                        }}
                    }}){{
                        object {{
                        id
                        }}
                    }}
                }}
                """.format(object_template['id'], object_template['name'], object_template['description'], object_template['editorgroup'], object_template['usergroup'], object_template['readergroup'], object_template['schemaId'], json.dumps(object_template['tags']))
            )
            result_create_object = client.execute(query_create_object)
    return 0

if __name__ == "__main__":
    logger.info("Initialize http-bridge module")
    setup_httpbridge_module(config)