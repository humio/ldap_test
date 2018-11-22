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