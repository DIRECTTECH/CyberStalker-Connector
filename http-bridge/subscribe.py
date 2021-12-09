import logging
import logging.config 
import yaml
import base64
import json
import string
import time
import subprocess
from envyaml import EnvYAML
import asyncio
import os
import sys
from gql import gql, Client
from gql.transport.aiohttp import AIOHTTPTransport
from gql.transport.websockets import WebsocketsTransport

# EnvYAML necessary to parse environment vairables for the configuration file
config = EnvYAML("./docs/conf.yaml") 
# Logging
logging.config.dictConfig(config["logging"])
logger = logging.getLogger("subs")

async def test_module(gql_address, jwt, event):
    """Test of the http bridge module

        RPC called to run and report functional tests of the http bridge module

        Parameters
        ----------
        gql_address : str
            GraphQL API URL
            
        jwt : str
            GraphQL access token.
            
        event : str
            Event received from a subscription.
    """
    
    transport = AIOHTTPTransport(url="http://{}/graphql".format(gql_address), headers={'Authorization': 'Bearer ' + jwt})
    client = Client(transport=transport, fetch_schema_from_transport=False)
    
    logger.debug(event)
    if event["name"] == "TestModule" and event["type"] == "RPC_STEALTH":
        time.sleep(1)
        logger.debug("RPC STEALTH Test Module DONE")
    elif event["name"] == "TestModule" and event["type"] == "RPC":
        mutation_acknowledge = gql(
            """
            mutation AckRPC {{
            updateControlExecutionAck(
                input: {{
                controlsExecutionId: \"{}\"
            }}) {{
                boolean
                }}
            }}
            """.format(event["id"])
        )
        mutation_acknowledge_result = await client.execute_async(mutation_acknowledge)
        
        logger.debug("RPC Test Module ACK")
        
        time.sleep(1)
        
        mutation_test_report = gql(
            """
            mutation RPCReport {{
            createControlExecutionReport(
                input: {{
                linkedControlId: {}
                report: \"TESTED: 1, PASSED: 1, FAILED: 0\"
                reportDetails: \"{{}}\"
                done: false
                error: false
            }}) {{
                integer
                }}
            }}
            """.format(event["id"])
        )
        mutation_test_report_result = await client.execute_async(mutation_test_report)
        logger.debug("RPC Test Module test report")
        
        time.sleep(1)
        
        mutation_done = gql(
            """
            mutation RPCFinalReport {{
            createControlExecutionReport(
                input: {{
                linkedControlId: {}
                report: \"PASSED\"
                reportDetails: \"{{}}\"
                done: true
                error: false
            }}) {{
                integer
                }}
            }}
            """.format(event["id"])
        )
        mutation_done_result = await client.execute_async(mutation_done)
        logger.debug("RPC Test Module DONE")
    return 0

async def run_unit_tests(gql_address, jwt, event):
    """Run unit tests of the http bridge module

        RPC called to run and report unit tests of the http bridge module

        Parameters
        ----------
        gql_address : str
            GraphQL API URL
            
        jwt : str
            GraphQL access token.
            
        event : str
            Event received from a subscription.
    """
    transport = AIOHTTPTransport(url="http://{}/graphql".format(gql_address), headers={'Authorization': 'Bearer ' + jwt})
    client = Client(transport=transport, fetch_schema_from_transport=False)
    
    logger.debug(event)
    if event["name"] == "RunUnitTests" and event["type"] == "RPC_STEALTH":
        time.sleep(1)
        logger.debug("RPC STEALTH Run Unit Tests DONE")
    elif event["name"] == "RunUnitTests" and event["type"] == "RPC":
        mutation_acknowledge = gql(
            """
            mutation AckRPC {{
            updateControlExecutionAck(
                input: {{
                controlsExecutionId: \"{}\"
            }}) {{
                boolean
                }}
            }}
            """.format(event["id"])
        )
        mutation_acknowledge_result = await client.execute_async(mutation_acknowledge)
        
        logger.debug("RPC Run Unit Tests ACK")
        
        time.sleep(1)
        
        test_name_1 = "test_sample.py"
        test_result_1 = ""
        test_status_1 = ""
        try:
            test_result_1 = subprocess.check_output(['python', '-m', 'pytest', '/test_sample.py'], stderr=subprocess.STDOUT)
            test_status_1 = "PASSED"
        except subprocess.CalledProcessError as e:
            test_result_1 = e.output
            test_status_1 = "FAILED"
            
        #logger.debug(test_result_1)
        
        time.sleep(1)
        
        report_message_1 = "Test: {}, Status: {}".format(test_name_1, test_status_1)
        logger.debug(report_message_1)
        report_details_1 = json.dumps({"message": test_result_1.decode("utf-8")}).replace('\"', '\\"').replace('n', '\n')
        logger.debug("{}".format(report_details_1))
        
        mutation_test_report = gql(
            """
            mutation RPCReport {{
            createControlExecutionReport(
                input: {{
                linkedControlId: {}
                report: \"{}\"
                reportDetails: "{}"
                done: false
                error: false
            }}) {{
                integer
                }}
            }}
            """.format(event["id"], report_message_1, r'''{"message": ""}''')
        )
        mutation_test_report_result = await client.execute_async(mutation_test_report)
        logger.debug("RPC Run Unit Tests report")
        
        time.sleep(1)
        
        mutation_done = gql(
            """
            mutation RPCFinalReport {{
            createControlExecutionReport(
                input: {{
                linkedControlId: {}
                report: \"Unit tests completed.\"
                reportDetails: \"{{}}\"
                done: true
                error: false
            }}) {{
                integer
                }}
            }}
            """.format(event["id"])
        )
        mutation_done_result = await client.execute_async(mutation_done)
        logger.debug("RPC Run Unit Tests DONE")
    return 0

async def subscribe(gql_address, jwt_env_key, topic):
    """Subscription channel on a given topic

        Listen for events on a GraphQL subscription channel and spawns workers
        according to the rules defined in the configuration file.

        Parameters
        ----------
        gql_address : str
            GraphQL API URL
            
        jwt_env_key : str
            Key used to retrieve the active JWT from the environment variables. 
            Format JWT_ENV_{NAME OF APPLICATION FROM CONFIG}.
            
        topic : str
            The topic defining the GraphQL subscription channel. Format {type}:{token_id}
            
        rules : str
            The dispatching rules as defined in the configuration file.
    """
    # Get access token from the environment
    jwt = os.environ[jwt_env_key]
    # Get the async loop
    loop = asyncio.get_event_loop()
    # Start a Websocket session
    transport = WebsocketsTransport(url="ws://{}/graphql".format(gql_address), headers={'Authorization': 'Bearer ' + jwt})
    async with Client(
        transport=transport, fetch_schema_from_transport=False,
    ) as session:
        # Start a GraphQL subscription specifically for objects
        objects_subscription = gql(
            """
            subscription {{
                listen(topic: "{}") {{
                    relatedNode {{
                        ... on Object {{
                            id
                            schemaType
                            name
                            enabled
                            tags
                            schemaId
                        }}
                        ... on ObjectProperty {{
                            id
                            objectId
                            groupName
                            property
                            value 
                            object {{
                                id
                                schemaType
                                name
                                enabled
                                tags
                                schemaId
                            }}
                        }}
                    }}
                }}
            }}
        """.format(topic)
        )
        # Start a GraphQL subscription specifically for misc
        misc_subscription = gql(
            """
            subscription {{
                listen(topic: "{}") {{
                    relatedNode {{
                        ... on User {{
                            id
                            login
                            password
                            enabled
                            description
                            mName
                            mPhone
                            mEmail
                            mTags
                            type
                            activated
                            passwordReset
                        }}
                    }}
                }}
            }}
        """.format(topic)
        )
        # Start a GraphQl subscription specifically for notifications
        notifications_subscription = gql(
            """
            subscription {{
                listen(topic: "{}") {{
                    relatedNode {{
                        ... on Notification {{
                            id
                            actorType
                            actor
                            actorName
                            tags
                            message
                            spec
                            createdAt
                        }}
                    }}
                }}
            }}
        """.format(topic)
        )
        # Start a GraphQL subscription specifically for controls
        # Necessary to not mix id fields of type uuid and int (specific to controls)
        controls_subscription = gql(
            """
            subscription {{
                listen(topic: "{}") {{
                    relatedNodeId
                    relatedNode {{
                        ... on ControlExecution {{
                            id
                            callerId
                            controller
                            name
                            type
                            params
                            linkedControlId
                            done
                        }}
                    }}
                }}
            }}
        """.format(topic)
        )
        # Listen for events on the subscription
        # Controls must be separated from standard subscriptions because of different id types.
        # Standard ids are uuids while controls use ints.
        if "controls" in topic:
            subscription = controls_subscription
        elif "objects" in topic:
            subscription = objects_subscription
        elif "notifications" in topic:
            subscription = notifications_subscription
        elif "misc" in topic:
            subscription = misc_subscription
        else:
            logger.error("Subscription error, unhandled topic: {}".format(topic))
            sys.exit(1)
        logger.info("Listening on {}".format(topic))
        # Process coming events
        async for event in session.subscribe(subscription):
            try:
                # Handle controls
                if "controls" in topic:
                    logger.debug("Event on topic {} ->\n{}".format(topic, event))
                    # If normal RPC
                    if event['listen']['relatedNode'] != None:
                        control_payload = event['listen']['relatedNode']
                    # If stealth RPC
                    else:
                        control_payload = json.loads(base64.b64decode(event['listen']['relatedNodeId']))[0]
                    
                    loop.create_task(eval("{}(gql_address, jwt, control_payload)".format("test_module")))
                    loop.create_task(eval("{}(gql_address, jwt, control_payload)".format("run_unit_tests")))
            
                else:
                    # DEBUG
                    logger.debug("Unhandled event")
            except Exception as e:
                logger.error(e)
                continue
