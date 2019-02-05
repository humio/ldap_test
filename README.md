# ldap_test
Testing for LDAP integrations

Simple tool for testing Humio LDAP configurations.

To invoke, run

```
> sbt "run $USER $PASSWORD"
```

the environment should contain the relevant configurations for HUMIO LDAP login, as described in
[the Humio documentation here](https://docs.humio.com/configuration/authentication/ldap/).

Here is a sample environment:

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

# Ubuntu
`sudo apt-get install libz-dev`

# Graalvm
To build a stand alone ahead-of-time optimized stand alone binary you'll need the `native-image` command from the GraalVM in your PATH.
`$ source <(curl -o - https://raw.githubusercontent.com/sbt/sbt-native-packager/master/.travis/download-graalvm)`

# Building
`sbt stage`
`sbt 'show graalvm-native-image:packageBin'`
or just `sbt graalvm-native-image:packageBin

# Run
./target/graalvm-native-image/hoot

# How to test with OpenLDAP

add to /etc/hosts on the line with `127.0.0.1  localhost` add `ldap.example.com`
test with `dig +short ldap.example.com` and expect to see `127.0.0.1`
`docker run --name ldap --hostname ldap.example.com --env LDAP_ORGANISATION="Example Company" --env LDAP_DOMAIN="example.com" --env LDAP_ADMIN_PASSWORD="password" --detach osixia/openldap:latest --loglevel debug`
insert a user
`docker exec $(docker ps -aqf "name=ldap") ldapadd -x -D "cn=admin,dc=example,dc=com" -f /container/service/slapd/assets/test/new-user.ldif -H ldap://ldap.example.com -w password -ZZ`

search for that user
```
docker exec 58 ldapsearch -x -H ldap://ldap.example.com -b dc=example,dc=com -D "cn=admin,dc=example,dc=com" -w password -ZZ
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

