# ldap_test
Testing for LDAP integrations

Simple tool for testing Humio LDAP configurations.

To invoke, run

```
> sbt "run $USER $PASSWORD"
```

the environment should contain the relevant configurations for HUMIO LDAP login, as described in
[the Humio documentation here](https://docs.humio.com/configuration/authentication/ldap/).
