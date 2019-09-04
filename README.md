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

Let's try via ldapsearch before using the ldap_test JAR:
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
address.  Here's the logic we use (in `getPrincipalName()` within the `Main.scala` file):

1. You provide `fry` and `LDAP_DOMAIN_NAME=planetexpress.com` which is transformed into `fry@planetexpress.com`, or...
2. you provide `fry@platnetexpress.com` which contains an `@` so we just use that, or...
3. you provide `fry@thiscantwork.com` same logic as #2 and the login will fail for that user, or...
4. you provide `ENTERPRISE\\fry` because you are used to Windows domain login, we spot the `\\` and transform that into `fry@planetexpress.com` again using the `LDAP_DOMAIN_NAME`
5. you provide `fry` but no `LDAP_DOMAIN_NAME` and we try to authenticate `fry` not `fry@planetexpress`

So, in the `ldapsearch` example we had a filter `(mail=fry@planetexpress.com)` anticipating the username to email
address translation we perform.  To make that filter work for any user we change the `fry@planetexpress.com` part
to `{0}` so that LDAP code makes the substitution for the username.  The filter should read,
`LDAP_SEARCH_FILTER=(& (mail={0}) (objectCategory=user))`.  If you'd like to match by user id (`uid`) then you'd
change the filter to read, `LDAP_SEARCH_FILTER=(& (uid={0}) (objectCategory=user))` and if that's the case the
the `LDAP_DOMAIN_NAME` must be blank (read: unset) and the user loging into Humio has to use just the
username (e.g. `fry`).  The default search filters are:
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
docker exec -it ldap-test ldapsearch -h 127.0.0.1 -p 389 -b "dc=planetexpress,dc=com" -w GoodNewsEveryone -D "cn=admin,dc=planetexpress,dc=com" -s sub -b "ou=people,dc=planetexpress,dc=com" "(& (objectClass=Group) (member=cn=Philip J. Fry,ou=people,dc=planetexpress,dc=com))"
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
Should compile and produce the uber Java archive (JAR) `target/scala-2.12/ldap-test-assembly-0.4.0-SNAPSHOT.jar`.  The steps
are:
 * `sbt clean`
 * `sbt assembly`

# Putting it all together and using the test JAR to validate

We're going to test as if someone typed user `fry` with password `fry` into Humio using the test JAR using first `sbt`
to run it the program.

```shell script
$ env AUTHENTICATION_METHOD=ldap-search LDAP_DOMAIN_NAME=planetexpress.com LDAP_AUTH_PROVIDER_URL="ldap://127.0.0.1:389" LDAP_SEARCH_BIND_NAME="cn=admin,dc=planetexpress,dc=com" LDAP_SEARCH_BIND_PASSWORD="GoodNewsEveryone" LDAP_SEARCH_FILTER="(& (mail={0}) (objectClass=person))" LDAP_SEARCH_BASE_DN="ou=people,dc=planetexpress,dc=com" LDAP_GROUP_BASE_DN="ou=people,dc=planetexpress,dc=com" LDAP_GROUP_FILTER="(& (objectClass=Group) (member={0}))" sbt '; set javaOptions ++= Seq("-Dlog4j.configuration=file:/resources/log4j_dev.properties", "-Dlog4j.appender.console.immediateFlush=true") ;runMain com.humio.ldap_test.Main fry@planetexpress.com fry'
  [info] Loading settings for project global-plugins from metals.sbt ...
  [info] Loading global plugins from /home/user/.sbt/1.0/plugins
  [info] Loading settings for project ldap_test-build from plugins.sbt ...
  [info] Loading project definition from /your/cwd/ldap_test/project
  [info] Loading settings for project root from build.sbt ...
  [info] Set current project to ldap-test (in build file:/your/cwd/ldap_test/)
  error: error while loading String, class file '/modules/java.base/java/lang/String.class' is broken
  (class java.lang.NullPointerException/null)
  [info] Defining javaOptions
  [info] The new value will be used by Compile / forkOptions, Compile / run / forkOptions and 8 others.
  [info] 	Run `last` for details.
  [info] Reapplying settings...
  [info] Set current project to ldap-test (in build file:/your/cwd/ldap_test/)
  [info] Formatting 1 Scala source ProjectRef(uri("file:/your/cwd/ldap_test/"), "root")(compile) ...
  [warn] Scalariform parser error for /your/cwd/ldap_test/src/main/scala/com/humio/ldap_test/Main.scala: illegal start of simple expression: Token(RPAREN,),692,))
  [info] Compiling 1 Scala source to /your/cwd/ldap_test/target/scala-2.12/classes ...
  [info] Done compiling.
  WARNING: An illegal reflective access operation has occurred
  WARNING: Illegal reflective access by com.google.protobuf.UnsafeUtil (file:/home/user/.sbt/boot/scala-2.12.7/org.scala-sbt/sbt/1.2.8/protobuf-java-3.3.1.jar) to field java.nio.Buffer.address
  WARNING: Please consider reporting this to the maintainers of com.google.protobuf.UnsafeUtil
  WARNING: Use --illegal-access=warn to enable warnings of further illegal reflective access operations
  WARNING: All illegal access operations will be denied in a future release
  [info] Packaging /your/cwd/ldap_test/target/scala-2.12/ldap-test_2.12-0.4.0-SNAPSHOT.jar ...
  [info] Done packaging.
  [info] Running (fork) com.humio.ldap_test.Main fry@planetexpress.com fry
  [info] 2019-08-27 14:28:17,743 INFO [main] c.h.l.Main$ [Main.scala:314]	Testing LDAP login for user=fry@planetexpress.com
  [info] 2019-08-27 14:28:17,930 INFO [main] c.h.l.LdapBindLocalLogin$ [Main.scala:68]	AUTHENTICATION_METHOD=LdapSearch
  [info] 2019-08-27 14:28:17,987 INFO [main] c.h.l.LdapBindLocalLogin$ [Main.scala:78]	ldapAuthConfig=Some(LdapAuthConfig(Some(ldap://127.0.0.1:389),None,Some(planetexpress.com),None,None,Some(cn=admin,dc=planetexpress,dc=com),Some(GoodNewsEveryone),Some(ou=people,dc=planetexpress,dc=com),None,Some((& (mail={0}) (objectClass=person))),Some(ou=people,dc=planetexpress,dc=com),Some((& (objectClass=Group) (member={0})))))
  [info] 2019-08-27 14:28:18,000 DEBUG [main] c.h.l.LdapBindLocalLogin$ [Main.scala:158]	ldap login for user=fry@planetexpress.com starting...
  [info] 2019-08-27 14:28:18,006 DEBUG [main] c.h.l.LdapBindLocalLogin$ [Main.scala:171]	initial dir context env={java.naming.factory.initial=com.sun.jndi.ldap.LdapCtxFactory, java.naming.provider.url=ldap://127.0.0.1:389, java.naming.security.principal=cn=admin,dc=planetexpress,dc=com, java.naming.security.authentication=simple, java.naming.security.credentials=GoodNewsEveryone}
  [info] 2019-08-27 14:28:18,045 DEBUG [main] c.h.l.LdapBindLocalLogin$ [Main.scala:174]	search: base=ou=people,dc=planetexpress,dc=com filter=(& (mail={0}) (objectClass=person)) args=List(fry@planetexpress.com)
  [info] 2019-08-27 14:28:18,059 DEBUG [main] c.h.l.LdapBindLocalLogin$ [Main.scala:179]	searching for user=fry@planetexpress.com in dn=cn=Philip J. Fry,ou=people,dc=planetexpress,dc=com filter=(& (mail={0}) (objectClass=person)) produced dn=cn=Philip J. Fry,ou=people,dc=planetexpress,dc=com
  [info] 2019-08-27 14:28:18,063 DEBUG [main] c.h.l.LdapBindLocalLogin$ [Main.scala:209]	login as user=fry@planetexpress.com dn=cn=Philip J. Fry,ou=people,dc=planetexpress,dc=com succeeded
  [info] 2019-08-27 14:28:18,064 DEBUG [main] c.h.l.LdapBindLocalLogin$ [Main.scala:212]	searching for group memberships within ldap for user=fry@planetexpress.com dn=cn=Philip J. Fry,ou=people,dc=planetexpress,dc=com within groupBaseDn=ou=people,dc=planetexpress,dc=com
  [info] 2019-08-27 14:28:18,065 DEBUG [main] c.h.l.LdapBindLocalLogin$ [Main.scala:221]	searching for the user=fry@planetexpress.com (dn=cn=Philip J. Fry,ou=people,dc=planetexpress,dc=com) within the groups in dn=ou=people,dc=planetexpress,dc=com filter=(& (objectClass=Group) (member={0})) args=[Ljava.lang.Object;@19d37183
  [info] 2019-08-27 14:28:18,084 DEBUG [main] c.h.l.LdapBindLocalLogin$ [Main.scala:227]	user=fry@planetexpress.com dn=cn=Philip J. Fry,ou=people,dc=planetexpress,dc=com is a member of 1 groups=[cn=ship_crew,ou=people,dc=planetexpress,dc=com]
  [info] 2019-08-27 14:28:18,087 INFO [main] c.h.l.LdapBindLocalLogin$ [Main.scala:95]	profile for loginService=AuthProviderProfile(Static,fry@planetexpress.com,fry@planetexpress.com,None,None,None,None,None,None)
  [info] 2019-08-27 14:28:18,087 INFO [main] c.h.l.Main$ [Main.scala:317]	Fantastic, that seems to have worked.
  [success] Total time: 6 s, completed Aug 27, 2019, 2:28:18 PM
```

Cool.  Next using `java -jar ...`

```shell script
env AUTHENTICATION_METHOD=ldap-search LDAP_DOMAIN_NAME=planetexpress.com LDAP_AUTH_PROVIDER_URL="ldap://127.0.0.1:389" LDAP_SEARCH_BIND_NAME="cn=admin,dc=planetexpress,dc=com" LDAP_SEARCH_BIND_PASSWORD="GoodNewsEveryone" LDAP_SEARCH_FILTER="(& (mail={0}) (objectClass=person))" LDAP_SEARCH_BASE_DN="ou=people,dc=planetexpress,dc=com" LDAP_GROUP_BASE_DN="ou=people,dc=planetexpress,dc=com" LDAP_GROUP_FILTER="(& (objectClass=Group) (member={0}))" java -jar ldap-test.jar fry@planetexpress.com fry
2019-08-28 10:32:14,235 INFO [main] c.h.l.Main$ [Main.scala:314]	Testing LDAP login for user=fry@planetexpress.com
2019-08-28 10:32:14,444 INFO [main] c.h.l.LdapBindLocalLogin$ [Main.scala:68]	AUTHENTICATION_METHOD=LdapSearch
2019-08-28 10:32:14,521 INFO [main] c.h.l.LdapBindLocalLogin$ [Main.scala:78]	ldapAuthConfig=Some(LdapAuthConfig(Some(ldap://127.0.0.1:389),None,Some(planetexpress.com),None,None,Some(cn=admin,dc=planetexpress,dc=com),Some(GoodNewsEveryone),Some(ou=people,dc=planetexpress,dc=com),None,Some((& (mail={0}) (objectClass=person))),Some(ou=people,dc=planetexpress,dc=com),Some((& (objectClass=Group) (member={0})))))
2019-08-28 10:32:14,538 DEBUG [main] c.h.l.LdapBindLocalLogin$ [Main.scala:158]	ldap login for user=fry@planetexpress.com starting...
2019-08-28 10:32:14,550 DEBUG [main] c.h.l.LdapBindLocalLogin$ [Main.scala:171]	initial dir context env={java.naming.factory.initial=com.sun.jndi.ldap.LdapCtxFactory, java.naming.provider.url=ldap://127.0.0.1:389, java.naming.security.principal=cn=admin,dc=planetexpress,dc=com, java.naming.security.authentication=simple, java.naming.security.credentials=GoodNewsEveryone}
2019-08-28 10:32:14,610 DEBUG [main] c.h.l.LdapBindLocalLogin$ [Main.scala:174]	search: base=ou=people,dc=planetexpress,dc=com filter=(& (mail={0}) (objectClass=person)) args=List(fry@planetexpress.com)
2019-08-28 10:32:14,626 DEBUG [main] c.h.l.LdapBindLocalLogin$ [Main.scala:179]	searching for user=fry@planetexpress.com in dn=cn=Philip J. Fry,ou=people,dc=planetexpress,dc=com filter=(& (mail={0}) (objectClass=person)) produced dn=cn=Philip J. Fry,ou=people,dc=planetexpress,dc=com
2019-08-28 10:32:14,631 DEBUG [main] c.h.l.LdapBindLocalLogin$ [Main.scala:209]	login as user=fry@planetexpress.com dn=cn=Philip J. Fry,ou=people,dc=planetexpress,dc=com succeeded
2019-08-28 10:32:14,631 DEBUG [main] c.h.l.LdapBindLocalLogin$ [Main.scala:212]	searching for group memberships within ldap for user=fry@planetexpress.com dn=cn=Philip J. Fry,ou=people,dc=planetexpress,dc=com within groupBaseDn=ou=people,dc=planetexpress,dc=com
2019-08-28 10:32:14,632 DEBUG [main] c.h.l.LdapBindLocalLogin$ [Main.scala:221]	searching for the user=fry@planetexpress.com (dn=cn=Philip J. Fry,ou=people,dc=planetexpress,dc=com) within the groups in dn=ou=people,dc=planetexpress,dc=com filter=(& (objectClass=Group) (member={0})) args=[Ljava.lang.Object;@2aa5fe93
2019-08-28 10:32:14,648 DEBUG [main] c.h.l.LdapBindLocalLogin$ [Main.scala:227]	user=fry@planetexpress.com dn=cn=Philip J. Fry,ou=people,dc=planetexpress,dc=com is a member of 1 groups=[cn=ship_crew,ou=people,dc=planetexpress,dc=com]
2019-08-28 10:32:14,651 INFO [main] c.h.l.LdapBindLocalLogin$ [Main.scala:95]	profile for loginService=AuthProviderProfile(Static,fry@planetexpress.com,fry@planetexpress.com,None,None,None,None,None,None)
2019-08-28 10:32:14,651 INFO [main] c.h.l.Main$ [Main.scala:317]	Fantastic, that seems to have worked.
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
Digest: sha256:64a6652b91930d2a2fb9f111db94fb5efcbd2ee2486548b3bd45f1504e9b4a4a
Status: Image is up to date for humio/humio-ldap-test:latest
$ docker run -it --rm --env-file .env humio-ldap-test fry fry
```
