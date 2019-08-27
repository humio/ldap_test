# 'ldap_test' is Humio's LDAP authentication stand-alone for testing. 

Test code for LDAP integration with Humio. Provide the same environment settings to this tool and it will
try to authenticate and fetch group membership from the LDAP (or ActiveDirectory) server you've specified.

To invoke, run:

```
$ sbt "run $USER $PASSWORD"
```

the environment should contain the relevant configurations for HUMIO LDAP login, as described in
[the Humio documentation here](https://docs.humio.com/configuration/authentication/ldap/).

# Sample environment for 'ldap' method:

```
export AUTHENTICATION_METHOD=ldap
export LDAP_DOMAIN_NAME=planetexpress.com
export LDAP_AUTH_PROVIDER_URL="ldap://127.0.0.1:389"
export LDAP_GROUP_BASE_DN="ou=people,dc=planetexpress,dc=com"
export LDAP_GROUP_FILTER="(& (objectClass=group) (member:1.2.840.113556.1.4.1941:={0}))"
```

# Sample environment for 'ldap-search' method:

```
export AUTHENTICATION_METHOD=ldap-search
export LDAP_SEARCH_BIND_NAME="$BIND_USER"
export LDAP_SEARCH_BIND_PASSWORD="$BIND_PASSWORD"
export LDAP_SEARCH_BASE_DN="OU=Humio,OU=User administration,DC=interprise,DC=dk"
export LDAP_SEARCH_FILTER="(& (sAMAccountName={0})(objectCategory=user))"
export LDAP_DOMAIN_NAME=humio.com
export LDAP_AUTH_PROVIDER_URL="ldap://dc.humio.com:389"
export LDAP_GROUP_BASE_DN="OU=User administration,DC=interprise,DC=dk"
export LDAP_GROUP_FILTER="(& (objectClass=group) (member:1.2.840.113556.1.4.1941:={0}))"
```

# Building
Java version 11 or 12 are required.

```
$ sbt stage
```
Will produce `target/scala-2.12/ldap-test_2.12-0.4.0-SNAPSHOT.jar`

# Testing

* Starting the test container with OpenLDAP and test data
```
docker pull rroemhild/test-openldap
docker run --name ldap-test --privileged -d -p 389:389 rroemhild/test-openldap
```

* Tail the logs of the OpenLDAP server in the docker container
```
docker logs -f $(docker ps -aqf "name=ldap-test")
```

* Search for all the records in the LDAP server using the example `admin` credentials
```
docker exec -it ldap-test ldapsearch -h 127.0.0.1 -D "cn=admin,dc=planetexpress,dc=com" -b "dc=planetexpress,dc=com" -w GoodNewsEveryone
```

* An example search for a user named 'Philip J. Fry' by 'uid'
```
$ docker exec -it ldap-test ldapsearch -h 127.0.0.1 -p 389 -b "dc=planetexpress,dc=com" -w GoodNewsEveryone -D "cn=admin,dc=planetexpress,dc=com" -s sub -b "ou=people,dc=planetexpress,dc=com" "uid=fry" "DN"
# extended LDIF
#
# LDAPv3
# base <ou=people,dc=planetexpress,dc=com> with scope subtree
# filter: uid=fry
# requesting: DN 
#

# Philip J. Fry, people, planetexpress.com
dn: cn=Philip J. Fry,ou=people,dc=planetexpress,dc=com

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

# How Humio (and this test) authenticate a username/password when using the "ldap" method

The username provided to Humio's login page is transformed into an email address using the `LDAP_DOMAIN_NAME`.  So if
`fry` tries to login we try to authenticate with LDAP with the username `fry@planetexpress.com` with this testing
dataset.

```
$ docker exec -it ldap-test ldapsearch -h 127.0.0.1 -p 389 -b "dc=planetexpress,dc=com" -w GoodNewsEveryone -D "cn=admin,dc=planetexpress,dc=com" -s sub -b "ou=people,dc=planetexpress,dc=com" "uid=fry" "DN"
```

# How Humio (and this test) search from a DN using the "ldap-search" method
"(& (userPrincipalName={0})(objectCategory=user))"
"(& (sAMAccountName={0})(objectCategory=user))"

```
docker exec -it ldap-test ldapsearch -h 127.0.0.1 -b "dc=planetexpress,dc=com" -D "uid=fry" -w fry
docker run --name ldap-test ldapsearch -x -H ldap://ldap.planetexpress.com -b dc=planetexpress,dc=com -D "email=fry@planetexpress.com" -w GoodNewsEveryone 
# extended LDIF
#
# LDAPv3
# base <dc=example,dc=com> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# example.com
dn: dc=example,dc=com
objectClass: top
objectClass: dcObject
objectClass: organization
o: Example Company
dc: example

# admin, example.com
dn: cn=admin,dc=example,dc=com
objectClass: simpleSecurityObject
objectClass: organizationalRole
cn: admin
description: LDAP administrator
userPassword:: e1NTSEF9TEZYQkM1UTBtQ3hSNWVFV3hGaGFDTVJmOWxZRlVnOGs=

# search result
search: 3
result: 0 Success

# numResponses: 3
# numEntries: 2
```

