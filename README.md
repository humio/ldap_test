# 'ldap_test' is Humio's LDAP authentication stand-alone for testing. 

Test code for LDAP integration with Humio. Provide the same environment settings to this tool and it will
try to authenticate and fetch group membership from the LDAP (or ActiveDirectory) server you've specified.

# Testing

* Starting the test container with OpenLDAP and test data
```shell script
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

# Sample environment for 'ldap' method to authenticate the 'fry' user:

```
export AUTHENTICATION_METHOD=ldap
export LDAP_DOMAIN_NAME=planetexpress.com
export LDAP_AUTH_PROVIDER_URL="ldap://127.0.0.1:389"
export LDAP_GROUP_BASE_DN="ou=people,dc=planetexpress,dc=com"
```

Let's try via ldapsearch before using the ldap_test JAR:
```shell script
$ docker exec -it ldap-test ldapsearch -h 127.0.0.1 -p 389 -b "dc=planetexpress,dc=com" -w fry -D "uid=fry,ou=people,dc=planetexpress,dc=com" -s sub -b "ou=people,dc=planetexpress,dc=com" "uid=fry" "DN"
ldap_bind: Invalid credentials (49)
```

Drat, it seems that the OpenLDAP testing container doesn't allow all logins to search, only `admin`.  This is
why the `ldap-search` method exists.

# Sample environment for 'ldap-search' method to authenticate 'fry' using the 'admin' account:

```
export AUTHENTICATION_METHOD=ldap-search
export LDAP_DOMAIN_NAME=planetexpress.com
export LDAP_AUTH_PROVIDER_URL="ldap://127.0.0.1:389"
export LDAP_SEARCH_BIND_NAME="cn=admin,ou=people,dc=planetexpress,dc=com"
export LDAP_SEARCH_BIND_PASSWORD="GoodNewsEveryone"
export LDAP_SEARCH_FILTER="(& (mail={0}) (objectClass=person))"
export LDAP_SEARCH_BASE_DN="ou=people,dc=planetexpress,dc=com"
export LDAP_GROUP_BASE_DN="ou=people,dc=planetexpress,dc=com"
export LDAP_GROUP_FILTER="(& (objectClass=Group) (member={0}))"
```

Let's try via ldapsearch tool before using the ldap_test JAR:
```shell script
docker exec -it ldap-test ldapsearch -h 127.0.0.1 -p 389 -b "dc=planetexpress,dc=com" -w GoodNewsEveryone -D "cn=admin,dc=planetexpress,dc=com" -s sub -b "ou=people,dc=planetexpress,dc=com" "(mail=fry@planetexpress.com)" "DN"
# extended LDIF
#
# LDAPv3
# base <ou=people,dc=planetexpress,dc=com> with scope subtree
# filter: (mail=fry@planetexpress.com)
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

Woot! We have searched for the DN that should be authenticated starting with the email address `fry@planetexpress.com`,
but wait... why did we search for an email address?  Well, when you login to Humio we change the user into an email
address unless you request that we use the value of an attribute on the user's record in LDAP
(`LDAP_USERNAME_ATTRIBUTE`).

If you're using an attribute from LDAP for the username by specifying `LDAP_USERNAME_ATTRIBUTE` then you'll need to
consider that in your filter as well.  Here's the previous query changed to use the `uid` for username.

```shell script
docker exec -it ldap-test ldapsearch -h 127.0.0.1 -p 389 -b "dc=planetexpress,dc=com" -w GoodNewsEveryone -D "cn=admin,dc=planetexpress,dc=com" -s sub -b "ou=people,dc=planetexpress,dc=com" "(uid=fry)" "uid"
# extended LDIF
#
# LDAPv3
# base <ou=people,dc=planetexpress,dc=com> with scope subtree
# filter: (uid=fry)
# requesting: uid 
#

# Philip J. Fry, people, planetexpress.com
dn: cn=Philip J. Fry,ou=people,dc=planetexpress,dc=com
uid: fry

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

Two things changed: the query filter became `(uid=fry)` as we're now going to match the value of that field rather than
email and `uid` as the attribute we're seeking within the record for this user.  The result shows the `dn` and the `uid`
and they are what we expect.

```shell script
# Philip J. Fry, people, planetexpress.com
dn: cn=Philip J. Fry,ou=people,dc=planetexpress,dc=com
uid: fry
```

If your LDAP administrator tells you that all users will have an `objectClass=person` then you can be a bit more
 specific in your search filter by combining (boolean and, `&`): `(&(objectClass=person)(uid=fry))`

Eventually, in Humio config for the search filter you'll replace the value your seeking with `{0}` so that query
would look like: `(&(objectClass=person)(uid={0}))`.

If you knew that some people typed in their email and others typed their user id (`uid`) then you could match either
by changing the filter to include both values in the search again combining the features (using boolean or, `|`):
`(&(objectClass=person)(|(uid={0})(mail={0})))`

If you specify 

If you don't specify `LDAP_USERNAME_ATTRIBUTE` or if you do *and* you specify `LDAP_SEARCH_DOMAIN_NAME` then Humio
will examine the provided username in the login and construct a new one that to use when searching.  Here's the logic:
see the function `getPrincipalName()` within the `Main.scala` file for how we construct the username from the text
provided by the user in the Humio login field.  In the case of LDAP Search substitute `LDAP_SEARCH_DOMAIN_NAME` for
`LDAP_DOMAIN_NAME` below.  Here's a rough approximation of that twisty/complex logic:

1. You provide `fry` and `LDAP_DOMAIN_NAME=planetexpress.com` which is transformed into `fry@planetexpress.com`, or...
2. you provide `fry@platnetexpress.com` which contains an `@` so we just use that, or...
3. you provide `fry@thiscantwork.com` same logic as #2 and the login will fail for that user, or...
4. you provide `ENTERPRISE\\fry` because you are used to Windows domain login, we spot the `\\` and transform that into `fry@planetexpress.com` again using the `LDAP_DOMAIN_NAME`
5. you provide `fry` but no `LDAP_DOMAIN_NAME` and we try to authenticate `fry` not `fry@planetexpress`

So, in the `ldapsearch` example we had a filter `(mail=fry@planetexpress.com)` anticipating the username to email
address translation we perform.  To make that filter work for any user we change the `fry@planetexpress.com` part
to `{0}` so that code makes the substitution for the username.  The filter should read,
`LDAP_SEARCH_FILTER=(& (mail={0}) (objectClass=person))`.  If you'd like to match by user id (`uid`) then you'd
change the filter to read, `LDAP_SEARCH_FILTER=(& (uid={0}) (objectClass=person))` and if that's the case the
the `LDAP_DOMAIN_NAME` must be blank (read: unset) and the user logging into Humio has to use just the
username (e.g. `fry`).  If you don't specify LDAP_SEARCH_FILTER then the two default search filters we try are:
 * `(& (userPrincipalName={0})(objectCategory=user))` and
 * `(& (sAMAccountName={0})(objectCategory=user))`
 
 Here we learn the joys of LDAP, it's a flexible standard.  In our test data we use `objectClass` not `objectCategory`.
 Also we use `person` not `user` and we have no `userPrincipalName` or `sAMAccountName`.  Those are common defaults, so
 there were good guesses, only in this case they would not have worked out of the box.  So we changed the way we search
 in the LDAP instance and life is good again.
 
# Role based authentication (RBAC) uses group membership provided by LDAP

The second thing LDAP does for Humio is to provide a list of groups a user belongs too for use when determining
RBAC permissions.  This is done by searching for group membership using the DN of the authenticated user.  In our test
case our user `fry` has a DN of `cn=Philip J. Fry,ou=people,dc=planetexpress,dc=com` which we found by searching
within LDAP for his email address (which is what the `ldap-search` configuration is all about).

Now that we have a DN for the user we just need a DN for the root of groups and the search filter to query with.  The
default filter is `(& (objectClass=group) (member:1.2.840.113556.1.4.1941:={0}))`, there is no default DN.  In our case
the `objectClass` is `Group` not `group`.  The magic number `1.2.840.113556.1.4.1941` informs LDAP to only return
objects that are currently a member of that group, not formerly a member.  For this example we'll use a group base DN
of `ou=people,dc=planetexpress,dc=com` and a filter `(& (objectClass=group) (member={0}))`.  Recall that the `{0}` bit
is just a place holder for the argument which in our case is the user's DN, or
`cn=Philip J. Fry,ou=people,dc=planetexpress,dc=com`.  We can test using `ldapsearch` first.

```shell script
docker exec -it ldap-test ldapsearch -h 127.0.0.1 -p 389 -b "dc=planetexpress,dc=com" -w GoodNewsEveryone -D "cn=admin,dc=planetexpress,dc=com" -s sub -b "ou=people,dc=planetexpress,dc=com" "(& (objectClass=group) (member=cn=Philip J. Fry,ou=people,dc=planetexpress,dc=com))"
# extended LDIF
#
# LDAPv3
# base <ou=people,dc=planetexpress,dc=com> with scope subtree
# filter: (& (objectClass=Group) (member=cn=Philip J. Fry,ou=people,dc=planetexpress,dc=com))
# requesting: ALL
#

# ship_crew, people, planetexpress.com
dn: cn=ship_crew,ou=people,dc=planetexpress,dc=com
objectClass: Group
objectClass: top
groupType: 2147483650
cn: ship_crew
member: cn=Philip J. Fry,ou=people,dc=planetexpress,dc=com
member: cn=Turanga Leela,ou=people,dc=planetexpress,dc=com
member:: Y249QmVuZGVyIEJlbmRpbmcgUm9kcsOtZ3VleixvdT1wZW9wbGUsZGM9cGxhbmV0ZXhwc
 mVzcyxkYz1jb20=

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

We note that the simple common name for groups is stored in the attribute `cn`, so we'll test again requesting that
attribute so that later we can use that for `LDAP_GROUPNAME_ATTRIBUTE`.

```shell shell script
docker exec -it ldap-test ldapsearch -h 127.0.0.1 -p 389 -b "dc=planetexpress,dc=com" -w GoodNewsEveryone -D "cn=admin,dc=planetexpress,dc=com" -s sub -b "ou=people,dc=planetexpress,dc=com" "(&(objectClass=group)(member=cn=Philip J. Fry,ou=people,dc=planetexpress,dc=com))" "cn"
# extended LDIF
#
# LDAPv3
# base <ou=people,dc=planetexpress,dc=com> with scope subtree
# filter: (&(objectClass=group)(member=cn=Philip J. Fry,ou=people,dc=planetexpress,dc=com))
# requesting: cn 
#

# ship_crew, people, planetexpress.com
dn: cn=ship_crew,ou=people,dc=planetexpress,dc=com
cn: ship_crew

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

# Building
Java version 11 or 12 and `sbt` (the Scala Build Tool), are required to build.  Use `sbt assembly` to build a JAR
that includes all dependencies of the project.

```shell script
$ sbt
  [info] Loading settings for project global-plugins from metals.sbt ...
  [info] Loading global plugins from /home/user/.sbt/1.0/plugins
  [info] Loading settings for project ldap_test-build from plugins.sbt ...
  [info] Loading project definition from /your/cwd/ldap_test/project
  [info] Loading settings for project root from build.sbt ...
  [info] Set current project to ldap-test (in build file:/your/cwd/ldap_test/)
  [info] sbt server started at local:///home/user/.sbt/1.0/server/c7d0fddc36b52e9eb8dd/sock
  sbt:ldap-test> clean
  [success] Total time: 0 s, completed Aug 28, 2019, 10:29:19 AM
  sbt:ldap-test> assembly
  [info] Updating ...
  [info] Formatting 1 Scala source ProjectRef(uri("file:/your/cwd/ldap_test/"), "root")(compile) ...
  [warn] Scalariform parser error for /your/cwd/ldap_test/src/main/scala/com/humio/ldap_test/Main.scala: illegal start of simple expression: Token(RPAREN,),692,))
  [info] Done updating.
  [info] Compiling 1 Scala source and 1 Java source to /your/cwd/ldap_test/target/scala-2.12/classes ...
  WARNING: An illegal reflective access operation has occurred
  WARNING: Illegal reflective access by sbt.internal.inc.javac.DiagnosticsReporter$PositionImpl$ (file:/home/user/.sbt/boot/scala-2.12.7/org.scala-sbt/sbt/1.2.8/zinc-compile-core_2.12-1.2.5.jar) to field com.sun.tools.javac.api.ClientCodeWrapper$DiagnosticSourceUnwrapper.d
  WARNING: Please consider reporting this to the maintainers of sbt.internal.inc.javac.DiagnosticsReporter$PositionImpl$
  WARNING: Use --illegal-access=warn to enable warnings of further illegal reflective access operations
  WARNING: All illegal access operations will be denied in a future release
  [warn] bootstrap class path not set in conjunction with -source 9
  [info] Done compiling.
  [info] Including: slf4j-api-1.7.25.jar
  [info] Including: logback-core-1.2.3.jar
  [info] Including: scala-logging_2.12-3.9.2.jar
  [info] Including: util-backports_2.12-2.0.jar
  [info] Including: logback-classic-1.2.3.jar
  [info] Including: scala-reflect-2.12.9.jar
  [info] Including: scala-library-2.12.9.jar
  [info] Checking every *.class/*.jar file's SHA-1.
  [info] Merging files...
  [warn] Merging 'NOTICE' with strategy 'rename'
  [warn] Merging 'LICENSE' with strategy 'rename'
  [warn] Merging 'META-INF/MANIFEST.MF' with strategy 'discard'
  [warn] Merging 'META-INF/maven/ch.qos.logback/logback-classic/pom.properties' with strategy 'discard'
  [warn] Merging 'META-INF/maven/ch.qos.logback/logback-classic/pom.xml' with strategy 'discard'
  [warn] Merging 'META-INF/maven/ch.qos.logback/logback-core/pom.properties' with strategy 'discard'
  [warn] Merging 'META-INF/maven/ch.qos.logback/logback-core/pom.xml' with strategy 'discard'
  [warn] Merging 'META-INF/maven/org.slf4j/slf4j-api/pom.properties' with strategy 'discard'
  [warn] Merging 'META-INF/maven/org.slf4j/slf4j-api/pom.xml' with strategy 'discard'
  [warn] Strategy 'discard' was applied to 7 files
  [warn] Strategy 'rename' was applied to 2 files
  [info] SHA-1: 89b2707924e1ddf4cb0050eeeda7eebd8b8813de
  [info] Packaging /your/cwd/ldap_test/target/scala-2.12/ldap-test-assembly-0.4.0-SNAPSHOT.jar ...
  [info] Done packaging.
  [success] Total time: 7 s, completed Aug 28, 2019, 10:29:30 AM
```
Should compile and produce the combined Java archive (JAR) `target/scala-2.12/ldap-test-assembly-0.4.0-SNAPSHOT.jar`.  The steps
are:
 * `sbt clean`
 * `sbt assembly`

# Putting it all together and using the test JAR to validate

We're going to test as if someone typed user `fry` with password `fry` into Humio using the test JAR using first `sbt`
to run it the program.  This example does not include `LDAP_SEARCH_DOMAIN_NAME` and so we'll search within LDAP for
`fry` when trying to identify this user.

```shell script
$ env AUTHENTICATION_METHOD=ldap-search LDAP_USERNAME_ATTRIBUTE=uid LDAP_GROUPNAME_ATTRIBUTE=cn LDAP_DOMAIN_NAME=planetexpress.com LDAP_AUTH_PROVIDER_URL="ldap://127.0.0.1:389" LDAP_SEARCH_BIND_NAME="cn=admin,dc=planetexpress,dc=com" LDAP_SEARCH_BIND_PASSWORD="GoodNewsEveryone" LDAP_SEARCH_FILTER="(&(objectClass=person)(|(uid={0})(mail={0})))" LDAP_SEARCH_BASE_DN="ou=people,dc=planetexpress,dc=com" LDAP_GROUP_BASE_DN="ou=people,dc=planetexpress,dc=com" LDAP_GROUP_FILTER="(& (objectClass=group) (member={0}))" sbt '; set javaOptions ++= Seq("-Dlog4j.configuration=file:/resources/log4j_dev.properties", "-Dlog4j.appender.console.immediateFlush=true") ;runMain com.humio.ldap_test.Main fry fry'
...
[info] running (fork) com.humio.ldap_test.Main fry fry
[info] 2019-10-10 10:15:12,289 INFO [main] c.h.l.Main$ [Main.scala:421] Testing LDAP login for user=fry
[info] 2019-10-10 10:15:12,415 INFO [main] c.h.l.LdapBindLocalLogin$ [Main.scala:69]    AUTHENTICATION_METHOD=LdapSearch
[info] 2019-10-10 10:15:12,482 INFO [main] c.h.l.LdapBindLocalLogin$ [Main.scala:79]    ldapAuthConfig=Some(LdapAuthConfig(Some(ldap://127.0.0.1:389),None,Some(planetexpress.com),None,None,Some(cn=admin,dc=planetexpress,dc=com),Some(GoodNewsEveryone),Some(ou=people,dc=planetexpress,dc=com),None,Some((&(objectClass=person)(|(uid={0})(mail={0})))),Some(ou=people,dc=planetexpress,dc=com),Some((& (objectClass=group) (member={0})))))
[info] 2019-10-10 10:15:12,491 DEBUG [main] c.h.l.LdapBindLocalLogin$ [Main.scala:166]  ldap login for username=fry starting...
[info] 2019-10-10 10:15:12,529 DEBUG [main] c.h.l.LdapBindLocalLogin$ [Main.scala:203]  initial dir context env={java.naming.factory.initial=com.sun.jndi.ldap.LdapCtxFactory, java.naming.provider.url=ldap://127.0.0.1:389, java.naming.security.principal=cn=admin,dc=planetexpress,dc=com, java.naming.security.authentication=simple, java.naming.security.credentials=GoodNewsEveryone}
[info] 2019-10-10 10:15:12,560 DEBUG [main] c.h.l.LdapBindLocalLogin$ [Main.scala:206]  search: base=ou=people,dc=planetexpress,dc=com filter=(&(objectClass=person)(|(uid={0})(mail={0}))) args=[fry]
[info] 2019-10-10 10:15:12,575 DEBUG [main] c.h.l.LdapBindLocalLogin$ [Main.scala:215]  ldap search username attribute uid=fry
[info] 2019-10-10 10:15:12,575 DEBUG [main] c.h.l.LdapBindLocalLogin$ [Main.scala:222]  searching for username=fry in ou=people,dc=planetexpress,dc=com filter=(&(objectClass=person)(|(uid={0})(mail={0}))) produced dn=Some(cn=Philip J. Fry,ou=people,dc=planetexpress,dc=com) attributed username=Some(fry)
[info] 2019-10-10 10:15:12,578 DEBUG [main] c.h.l.LdapBindLocalLogin$ [Main.scala:255]  login as username=fry dn=cn=Philip J. Fry,ou=people,dc=planetexpress,dc=com succeeded
[info] 2019-10-10 10:15:12,579 DEBUG [main] c.h.l.LdapBindLocalLogin$ [Main.scala:258]	searching for group memberships within ldap for username=fry dn=cn=Philip J. Fry,ou=people,dc=planetexpress,dc=com within groupBaseDn=ou=people,dc=planetexpress,dc=com
[info] 2019-10-10 10:15:12,580 DEBUG [main] c.h.l.LdapBindLocalLogin$ [Main.scala:271]	searching for the username=fry (dn=cn=Philip J. Fry,ou=people,dc=planetexpress,dc=com) within the groups in groupDn=ou=people,dc=planetexpress,dc=com filter=(& (objectClass=group) (member={0})) args=[cn=Philip J. Fry,ou=people,dc=planetexpress,dc=com]
[info] 2019-10-10 10:15:12,582 DEBUG [main] c.h.l.LdapBindLocalLogin$ [Main.scala:281]	ldap search groupname attribute cn=ship_crew
[info] 2019-10-10 10:15:12,595 DEBUG [main] c.h.l.LdapBindLocalLogin$ [Main.scala:306]	username=fry dn=cn=Philip J. Fry,ou=people,dc=planetexpress,dc=com is a member of 1 groups=[ship_crew] groupDns=[cn=ship_crew,ou=people,dc=planetexpress,dc=com]
[info] 2019-10-10 10:15:12,598 INFO [main] c.h.l.LdapBindLocalLogin$ [Main.scala:100]	authenticated username=fry email=Some(fry@planetexpress.com) with profile for loginService=AuthProviderProfile(Static,fry@planetexpress.com,fry,Some(Some(fry@planetexpress.com)),None,None,None,None,None)
[info] 2019-10-10 10:15:12,598 INFO [main] c.h.l.Main$ [Main.scala:424]	Fantastic, that seems to have worked.
```

In this next example we change one thing, we provide `LDAP_SEARCH_DOMAIN_NAME=planetexpress.com` which will change what
we search for when locating the user's record in LDAP from `fry` to `fry@planetexpress.com`.  Good thing our search
filter checks both `uid` and `mail`, this time we'll match on `mail`.

```shell script
env AUTHENTICATION_METHOD=ldap-search LDAP_USERNAME_ATTRIBUTE=uid LDAP_GROUPNAME_ATTRIBUTE=cn LDAP_DOMAIN_NAME=planetexpress.com LDAP_AUTH_PROVIDER_URL="ldap://127.0.0.1:389" LDAP_SEARCH_DOMAIN_NAME=planetexpress.com LDAP_SEARCH_BIND_NAME="cn=admin,dc=planetexpress,dc=com" LDAP_SEARCH_BIND_PASSWORD="GoodNewsEveryone" LDAP_SEARCH_FILTER="(&(objectClass=person)(|(uid={0})(mail={0})))" LDAP_SEARCH_BASE_DN="ou=people,dc=planetexpress,dc=com" LDAP_GROUP_BASE_DN="ou=people,dc=planetexpress,dc=com" LDAP_GROUP_FILTER="(& (objectClass=group) (member={0}))" sbt '; set javaOptions ++= Seq("-Dlog4j.configuration=file:/resources/log4j_dev.properties", "-Dlog4j.appender.console.immediateFlush=true") ;runMain com.humio.ldap_test.Main fry fry'
...
[info] running (fork) com.humio.ldap_test.Main fry fry
[info] 2019-10-10 10:25:28,038 INFO [main] c.h.l.Main$ [Main.scala:421] Testing LDAP login for user=fry
[info] 2019-10-10 10:25:28,263 INFO [main] c.h.l.LdapBindLocalLogin$ [Main.scala:69]    AUTHENTICATION_METHOD=LdapSearch
[info] 2019-10-10 10:25:28,350 INFO [main] c.h.l.LdapBindLocalLogin$ [Main.scala:79]    ldapAuthConfig=Some(LdapAuthConfig(Some(ldap://127.0.0.1:389),None,Some(planetexpress.com),None,None,Some(cn=admin,dc=planetexpress,dc=com),Some(GoodNewsEveryone),Some(ou=people,dc=planetexpress,dc=com),Some(planetexpress.com),Some((&(objectClass=person)(|(uid={0})(mail={0})))),Some(ou=people,dc=planetexpress,dc=com),Some((& (objectClass=group) (member={0})))))
[info] 2019-10-10 10:25:28,361 DEBUG [main] c.h.l.LdapBindLocalLogin$ [Main.scala:166]  ldap login for username=fry starting...
[info] 2019-10-10 10:25:28,403 DEBUG [main] c.h.l.LdapBindLocalLogin$ [Main.scala:203]  initial dir context env={java.naming.factory.initial=com.sun.jndi.ldap.LdapCtxFactory, java.naming.provider.url=ldap://127.0.0.1:389, java.naming.security.principal=cn=admin,dc=planetexpress,dc=com, java.naming.security.authentication=simple, java.naming.security.credentials=GoodNewsEveryone}
[info] 2019-10-10 10:25:28,463 DEBUG [main] c.h.l.LdapBindLocalLogin$ [Main.scala:206]  search: base=ou=people,dc=planetexpress,dc=com filter=(&(objectClass=person)(|(uid={0})(mail={0}))) args=[fry@planetexpress.com]
[info] 2019-10-10 10:25:28,485 DEBUG [main] c.h.l.LdapBindLocalLogin$ [Main.scala:215]  ldap search username attribute uid=fry
[info] 2019-10-10 10:25:28,485 DEBUG [main] c.h.l.LdapBindLocalLogin$ [Main.scala:222]  searching for username=fry in ou=people,dc=planetexpress,dc=com filter=(&(objectClass=person)(|(uid={0})(mail={0}))) produced dn=Some(cn=Philip J. Fry,ou=people,dc=planetexpress,dc=com) attributed username=Some(fry)
[info] 2019-10-10 10:25:28,488 DEBUG [main] c.h.l.LdapBindLocalLogin$ [Main.scala:255]  login as username=fry dn=cn=Philip J. Fry,ou=people,dc=planetexpress,dc=com succeeded
[info] 2019-10-10 10:25:28,489 DEBUG [main] c.h.l.LdapBindLocalLogin$ [Main.scala:258]	searching for group memberships within ldap for username=fry dn=cn=Philip J. Fry,ou=people,dc=planetexpress,dc=com within groupBaseDn=ou=people,dc=planetexpress,dc=com
[info] 2019-10-10 10:25:28,490 DEBUG [main] c.h.l.LdapBindLocalLogin$ [Main.scala:271]	searching for the username=fry (cn=Philip J. Fry,ou=people,dc=planetexpress,dc=com) within the groups in groupDn=ou=people,dc=planetexpress,dc=com filter=(& (objectClass=group) (member={0})) args=[cn=Philip J. Fry,ou=people,dc=planetexpress,dc=com]
[info] 2019-10-10 10:25:28,492 DEBUG [main] c.h.l.LdapBindLocalLogin$ [Main.scala:281]	ldap search groupname attribute cn=ship_crew
[info] 2019-10-10 10:25:28,521 DEBUG [main] c.h.l.LdapBindLocalLogin$ [Main.scala:306]	username=fry dn=cn=Philip J. Fry,ou=people,dc=planetexpress,dc=com is a member of 1 groups=[ship_crew] dn=[cn=ship_crew,ou=people,dc=planetexpress,dc=com]
[info] 2019-10-10 10:25:28,526 INFO [main] c.h.l.LdapBindLocalLogin$ [Main.scala:100]	authenticated username=fry email=Some(fry@planetexpress.com) with profile for loginService=AuthProviderProfile(Static,fry@planetexpress.com,fry,Some(Some(fry@planetexpress.com)),None,None,None,None,None)
[info] 2019-10-10 10:25:28,526 INFO [main] c.h.l.Main$ [Main.scala:424]	Fantastic, that seems to have worked.
```

Here's the line from above that shows the difference:
```shell script
[info] 2019-10-10 10:25:28,463 DEBUG [main] c.h.l.LdapBindLocalLogin$ [Main.scala:206]  search: base=ou=people,dc=planetexpress,dc=com filter=(&(objectClass=person)(|(uid={0})(mail={0}))) args=[fry@planetexpress.com]
```

Note `args` in this case is `fry@planetexpress.com` whereas before, without having set `LDAP_SEARCH_DOMAIN_NAME` it was
simply `args=[fry]`.

Cool.  Next using `java -jar ...` without `LDAP_SEARCH_DOMAIN_NAME` set as before.

```shell script
env AUTHENTICATION_METHOD=ldap-search LDAP_USERNAME_ATTRIBUTE=uid LDAP_GROUPNAME_ATTRIBUTE=cn LDAP_DOMAIN_NAME=planetexpress.com LDAP_AUTH_PROVIDER_URL="ldap://127.0.0.1:389" LDAP_SEARCH_BIND_NAME="cn=admin,dc=planetexpress,dc=com" LDAP_SEARCH_BIND_PASSWORD="GoodNewsEveryone" LDAP_SEARCH_FILTER="(&(objectClass=person)(|(uid={0})(mail={0})))" LDAP_SEARCH_BASE_DN="ou=people,dc=planetexpress,dc=com" LDAP_GROUP_BASE_DN="ou=people,dc=planetexpress,dc=com" LDAP_GROUP_FILTER="(& (objectClass=group) (member={0}))" java -jar target/scala-2.12/ldap-test-assembly-0.4.0-SNAPSHOT.jar fry fry
2019-10-10 10:35:02,764 INFO [main] c.h.l.Main$ [Main.scala:421]	Testing LDAP login for user=fry
2019-10-10 10:35:02,927 INFO [main] c.h.l.LdapBindLocalLogin$ [Main.scala:69]	AUTHENTICATION_METHOD=LdapSearch
2019-10-10 10:35:03,015 INFO [main] c.h.l.LdapBindLocalLogin$ [Main.scala:79]	ldapAuthConfig=Some(LdapAuthConfig(Some(ldap://127.0.0.1:389),None,Some(planetexpress.com),None,None,Some(cn=admin,dc=planetexpress,dc=com),Some(GoodNewsEveryone),Some(ou=people,dc=planetexpress,dc=com),None,Some((&(objectClass=person)(|(uid={0})(mail={0})))),Some(ou=people,dc=planetexpress,dc=com),Some((& (objectClass=group) (member={0})))))
2019-10-10 10:35:03,026 DEBUG [main] c.h.l.LdapBindLocalLogin$ [Main.scala:166]	ldap login for username=fry starting...
2019-10-10 10:35:03,071 DEBUG [main] c.h.l.LdapBindLocalLogin$ [Main.scala:203]	initial dir context env={java.naming.factory.initial=com.sun.jndi.ldap.LdapCtxFactory, java.naming.provider.url=ldap://127.0.0.1:389, java.naming.security.principal=cn=admin,dc=planetexpress,dc=com, java.naming.security.authentication=simple, java.naming.security.credentials=GoodNewsEveryone}
2019-10-10 10:35:03,119 DEBUG [main] c.h.l.LdapBindLocalLogin$ [Main.scala:206]	search: base=ou=people,dc=planetexpress,dc=com filter=(&(objectClass=person)(|(uid={0})(mail={0}))) args=[fry]
2019-10-10 10:35:03,149 DEBUG [main] c.h.l.LdapBindLocalLogin$ [Main.scala:215]	ldap search username attribute uid=fry
2019-10-10 10:35:03,149 DEBUG [main] c.h.l.LdapBindLocalLogin$ [Main.scala:222]	searching for username=fry in ou=people,dc=planetexpress,dc=com filter=(&(objectClass=person)(|(uid={0})(mail={0}))) produced dn=Some(cn=Philip J. Fry,ou=people,dc=planetexpress,dc=com) attributed username=Some(fry)
2019-10-10 10:35:03,153 DEBUG [main] c.h.l.LdapBindLocalLogin$ [Main.scala:255]	login as username=fry dn=cn=Philip J. Fry,ou=people,dc=planetexpress,dc=com succeeded
2019-10-10 10:35:03,154 DEBUG [main] c.h.l.LdapBindLocalLogin$ [Main.scala:258]	searching for group memberships within ldap for username=fry dn=cn=Philip J. Fry,ou=people,dc=planetexpress,dc=com within groupBaseDn=ou=people,dc=planetexpress,dc=com
2019-10-10 10:35:03,155 DEBUG [main] c.h.l.LdapBindLocalLogin$ [Main.scala:271]	searching for the username=fry (dn=cn=Philip J. Fry,ou=people,dc=planetexpress,dc=com) within the groups in groupDn=ou=people,dc=planetexpress,dc=com filter=(& (objectClass=group) (member={0})) args=[cn=Philip J. Fry,ou=people,dc=planetexpress,dc=com]
2019-10-10 10:35:03,157 DEBUG [main] c.h.l.LdapBindLocalLogin$ [Main.scala:281]	ldap search groupname attribute cn=ship_crew
2019-10-10 10:35:03,175 DEBUG [main] c.h.l.LdapBindLocalLogin$ [Main.scala:306]	username=fry dn=cn=Philip J. Fry,ou=people,dc=planetexpress,dc=com is a member of 1 groups=[ship_crew] groupDns=[cn=ship_crew,ou=people,dc=planetexpress,dc=com]
2019-10-10 10:35:03,184 INFO [main] c.h.l.LdapBindLocalLogin$ [Main.scala:100]	authenticated username=fry email=Some(fry@planetexpress.com) with profile for loginService=AuthProviderProfile(Static,fry@planetexpress.com,fry,Some(Some(fry@planetexpress.com)),None,None,None,None,None)
2019-10-10 10:35:03,184 INFO [main] c.h.l.Main$ [Main.scala:424]	Fantastic, that seems to have worked.
```

Fantastic, that seems to have worked.  We authenticated with the OpenLDAP instance using `admin`'s credentials and
searched for `fry`'s DN then used that to find out that he's a member of the `ship_crew` group.  Our work is done,
but it could have been easier...

# Docker test image of this repo

When you configure Humio you'll add to a file in `/etc/humio` that has many configuration settings, some for LDAP.  All
you have to do is run the docker image pre-built with the JAR from this repo and reference that configuration file in
order to test using this tool.  Example config for LDAP is in
https://github.com/humio/ldap-test-image/blob/master/.env.example`.

The config read from the environment should contain the relevant configurations for Humio LDAP login, as described in
[the Humio documentation here](https://docs.humio.com/configuration/authentication/ldap/).


```shell script
$ cat > .env <<EOF
  AUTHENTICATION_METHOD=ldap-search
  LDAP_DOMAIN_NAME=planetexpress.com
  LDAP_AUTH_PROVIDER_URL="ldap://127.0.0.1:389"
  LDAP_SEARCH_BIND_NAME="cn=admin,ou=people,dc=planetexpress,dc=com"
  LDAP_SEARCH_BIND_PASSWORD="GoodNewsEveryone"
  LDAP_SEARCH_FILTER="(& (mail={0}) (objectClass=person))"
  LDAP_SEARCH_BASE_DN="ou=people,dc=planetexpress,dc=com"
  LDAP_GROUP_BASE_DN="ou=people,dc=planetexpress,dc=com"
  LDAP_GROUP_FILTER="(& (objectClass=Group) (member={0}))"
EOF
$ docker pull humio/humio-ldap-test:latest
latest: Pulling from humio/humio-ldap-test
Digest: sha256:3141af6f5e8b033b8412b7350cf2b00e2a97194fbe0d692ca8a232ad13ac2c7f
Status: Image is up to date for humio/humio-ldap-test:latest
$ docker run -it --rm --env-file .env humio/humio-ldap-test fry fry
```
