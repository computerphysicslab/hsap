HSAP
====

HSAP Open Source projects
-------------------------

- [Introduction](#introduction)
- [Items](#items)
- [Deployment](#deployment)


#### Introducción

These are docker-deployable goLang APIs and packages encompassing SNMP services for network managment


#### Items

```text
1.- libsnmp
	goLang package to perform SNMP queries

2.- libstruct
	goLang package to handle structs, pretty format for debug

3.- snmpswitch
	goLang service to explore network switches and IPs
```


#### Deployment

To deploy an API snmpswitch service w/ docker:

```text
git init
git clone https://github.com/computerphysicslab/hsap.git
cd hsap/snmpswitch/api/
Create hsapNetwork.yaml as your network map, based upon myNetwork template => https://github.com/computerphysicslab/hsap/blob/master/snmpswitch/example/myNetwork.yaml
sudo docker build -t hsap/apiswitch .
sudo docker run -p 3333:3333 hsap/apiswitch
```
