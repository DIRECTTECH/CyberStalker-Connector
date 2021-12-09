# CyberStalker-Connector

Based on machine learning, CyberStalker Connector facilitates and secures the data transmission both between the nodes within infrastructure and different modules inside it. Metrics collected, client libraries, customized data - the user gains the full insight of the network in use at no cost in no time. CyberStalker Connector unifies the data from the systems, applications and networks, assisting the user to configure it. Besides, CyberStalker Connector can be used to discover and backup end nodes that are connected to firewall blades that are managed by the security systems.

HTTP Bridge which allows injection of the data into o the Platform and execution of RPC calls over HTTP.

----
## HTTP Requests

### Update properties

```
POST http-bridge:5060/<OBJECT_UUID>/properties
```

```json
[
    {
        "groupname_1/property1": "value1",
        "groupname_1/property2": "value2",
        "groupname_2/property1": "value3"
    }
]
```

### RPC

```
POST http-bridge:5060/<OBJECT_UUID>/control
```

```json
{
    "rpc": "NameOfRpc",
    "params": {
        "parameter1": "value1",
        "parameter2": "value2",
        "parameter3": "value3"
    }
}
```

### Stealth RPC

```
POST http-bridge:5060/<OBJECT_UUID>/control/stealth
```

```json
{
    "rpc": "NameOfRpc",
    "params": {
        "parameter1": "value1",
        "parameter2": "value2",
        "parameter3": "value3"
    }
}
```