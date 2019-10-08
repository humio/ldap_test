package com.humio.ldap_test

import java.util

import ch.qos.logback.classic.encoder.PatternLayoutEncoder
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.classic.{ Level, LoggerContext }
import ch.qos.logback.core.ConsoleAppender
import javax.naming.NamingException
import javax.naming.directory.{ InitialDirContext, SearchControls }
import org.slf4j.LoggerFactory

import scala.collection.JavaConverters._
import scala.util.Try

sealed abstract class LdapConnectionMethod(url: String) {
  def env(): Map[String, String] = {
    Map(
      javax.naming.Context.INITIAL_CONTEXT_FACTORY -> "com.sun.jndi.ldap.LdapCtxFactory",
      javax.naming.Context.SECURITY_AUTHENTICATION -> "simple",
    )
  }
}
case class UnsecuredLdapConnection(url: String) extends LdapConnectionMethod(url) {
  require(url.startsWith("ldap:"), "The LDAP endpoint must begin with 'ldap:' not " + url.take(5))
}
case class SecuredLdapConnection(url: String, cert: Option[String] = None) extends LdapConnectionMethod(url) {
  require(url startsWith "ldaps:", "The LDAP over SSL/TLS endpoint must begin with 'ldaps:' not " + url.take(6))

  override def env(): Map[String, String] = {
    super.env ++
    Map(
      javax.naming.Context.SECURITY_PROTOCOL -> Option("ssl"),
      cert match {
        case None => "" -> None
        case Some(c) =>
          SelfSignedSSLSocketFactory.setCertificate(c)
          "java.naming.ldap.factory.socket" -> Option(SelfSignedSSLSocketFactory.name())
      }
    ).filter(_._2.isDefined).mapValues(_.get)
  }
}

sealed abstract class LdapPrincipal
case class LdapKnownPrincipal(principal: String) extends LdapPrincipal
case class LdapPrincipalSearch(username: String, password: String, dn: String, filter: String, transformUsernameToPrincipal: String => String) extends LdapPrincipal

case class LdapAuth(conn: LdapConnectionMethod, principals: Seq[LdapPrincipal])

case class LdapGroupLookup(dn: String, filter: String)

//class LdapBindLocalLogin(loginService: LoginService, config: Config) extends LocalLogin {
object LdapBindLocalLogin {
  private val logger = Logger.forObject(this)

  def login(username: String, pass: String): Boolean = {
    if (username.isBlank) {
      logger.info(s"missing username in login request")
      LocalLogin.loginFailure
    } else if (pass.isBlank) {
      logger.info(s"missing password in login request")
      LocalLogin.loginFailure
    } else {
      val authenticationMethod = sys.env.get("AUTHENTICATION_METHOD") match {
        case Some(method) if method.equals("ldap") =>
          logger.info("AUTHENTICATION_METHOD=Ldap")
          AuthenticationMethod.Ldap
        case Some(method) if method.equals("ldap-search") =>
          logger.info("AUTHENTICATION_METHOD=LdapSearch")
          AuthenticationMethod.LdapSearch
        case Some(method) =>
          logger.error(s"This tool tests LDAP authentication, not $method.")
          AuthenticationMethod.NoAuthentication
        case None =>
          logger.error(s"Missing environment variable AUTHENTICATION_METHOD")
          AuthenticationMethod.NoAuthentication
      }
      val ldapConfig = ldapConfigFromEnv()
      logger.info(s"ldapAuthConfig=$ldapConfig")
      ldapConfig match {
        case None => LocalLogin.loginFailure
        case Some(ldapAuthConfig) =>
          if (username.isBlank) {
            logger.info(s"missing username in login request")
            LocalLogin.loginFailure
          } else if (pass.isBlank) {
            logger.info(s"missing password in login request")
            LocalLogin.loginFailure
          } else {
            val domain = ldapAuthConfig.ldapDomainName.getOrElse("")
            val providerUsername = getPrincipalName(username, domain)
            val ldapAuth = ldapAuthFromConfig(authenticationMethod, domain, ldapAuthConfig)
            openLdapContext(username, pass, ldapAuthConfig.ldapAuthProviderUrl.get, ldapAuth, ldapAuthConfig.ldapGroupBaseDn, ldapAuthConfig.ldapGroupFilter) match {
            case (Some(_), requestedUsername, groups) =>
              val profile = AuthProviderProfile(
                provider = "Static",
                authProviderUsername = providerUsername,
                humioUsername = requestedUsername.getOrElse(providerUsername),
                email = Option(Option(providerUsername)))
                logger.info(s"profile for loginService=$profile")
              true // loginService.login(profile, optionals, groups)
              case _ => LocalLogin.loginFailure
            }
          }
      }
    }
  }

  private def ldapAuthFromConfig(kind: AuthenticationMethod.Value, domain: String, ldapAuthConfig: LdapAuthConfig): LdapAuth = {
    val splitPrincipals = ldapAuthConfig.ldapAuthPrincipalsRegex
    val connectionMethod = ldapAuthConfig.ldapAuthProviderUrl match {
      case Some(url) if url.startsWith("ldap:") => UnsecuredLdapConnection(url)
      case Some(url) if url.startsWith("ldaps:") => SecuredLdapConnection(url, ldapAuthConfig.ldapAuthProviderCert)
      case None => throw new HumioException(s"The LDAP authentication URL is missing or incorrect. LDAP_AUTH_PROVIDER_URL=${ldapAuthConfig.ldapAuthProviderUrl}")
    }
    val principals = kind match {
        case AuthenticationMethod.Ldap =>
          (ldapAuthConfig.ldapAuthPrincipal match {
            case Some(principals) if principals.nonEmpty && splitPrincipals.isDefined =>
              principals.split(splitPrincipals.get).toSeq
            case Some(principal) if principal.nonEmpty =>
              Seq(principal)
            case _ =>
              Seq(getPrincipalName("HUMIOUSERNAME", domain))
          }).map(principal => LdapKnownPrincipal(principal))
        case AuthenticationMethod.LdapSearch =>
          (ldapAuthConfig.ldapSearchBindName, ldapAuthConfig.ldapSearchBindPassword, ldapAuthConfig.ldapSearchBaseDn) match {
            case (Some(searchBindName), Some(searchBindPassword), Some(searchBaseDn)) =>
              ldapAuthConfig.ldapSearchFilter match {
                case None =>
                  Seq(
                    LdapPrincipalSearch(searchBindName, searchBindPassword, searchBaseDn, "(& (userPrincipalName={0})(objectCategory=user))",
                      username => getPrincipalName(username, ldapAuthConfig.ldapSearchDomainName.getOrElse(domain))),
                    LdapPrincipalSearch(searchBindName, searchBindPassword, searchBaseDn, "(& (sAMAccountName={0})(objectCategory=user))",
                      username => {
                        val principalName = getPrincipalName(username, ldapAuthConfig.ldapSearchDomainName.getOrElse(domain))
                        principalName.substring(0, principalName.indexOf('@'))
                      }))
                case Some(filter) =>
                  Seq(LdapPrincipalSearch(searchBindName, searchBindPassword, searchBaseDn, filter,
                  username => ldapAuthConfig.ldapSearchDomainName match {
                    case Some(name) => getPrincipalName(username, name)
                    case None => username
                  }))
              }
            case _ =>
              logger.error(s"Missing information required to perform ldap-search. LDAP_SEARCH_BIND_NAME=${ldapAuthConfig.ldapSearchBindName} LDAP_SEARCH_BIND_PASSWORD=${if (ldapAuthConfig.ldapSearchBindPassword.isEmpty) "empty" else "REDACTED"} LDAP_SEARCH_BASE_DN=${ldapAuthConfig.ldapSearchBaseDn}")
              Seq.empty
          }
      }
    LdapAuth(connectionMethod, principals)
  }

  private def ldapEnv(url: String, dn: String, secret: String, env: Map[String, String]): util.Hashtable[String, String] = {
    if (dn.isEmpty || secret.isEmpty) {
      throw new javax.naming.AuthenticationException("Missing LDAP credentials, unable to attempt login.")
    }
    new util.Hashtable[String, String](
      (env ++ Map(
        javax.naming.Context.PROVIDER_URL -> url,
        javax.naming.Context.SECURITY_PRINCIPAL -> dn,
        javax.naming.Context.SECURITY_CREDENTIALS -> secret)).asJava)
  }

  private def openLdapContext(username: String, password: String, url: String, ldapAuth: LdapAuth, ldapGroupBaseDn: Option[String], ldapGroupFilter: Option[String]): (Option[String], Option[String], Seq[String]) = {
    logger.debug(s"ldap login for username=$username starting...")
    var ctx: InitialDirContext = null
    val usernameAttribute = sys.env.get("LDAP_USERNAME_ATTRIBUTE")
    val groupnameAttribute = sys.env.get("LDAP_GROUPNAME_ATTRIBUTE")

    def isServerAvailable(url: String): Boolean = {
      import java.net.Socket
      val pattern = """^ldaps?://([^:]+)(:([0-9]+))?$""".r
      pattern.findFirstMatchIn(url) match {
        case Some(result) =>
          val host = result.group(1)
          val port = Option(result.group(3)) match {
            case Some(p) => Try(p.toInt).getOrElse(389)
            case None => 389
          }
          Try(new Socket(host, port).close()).isSuccess
        case None =>
          false
      }
    }

    if (isServerAvailable(url)) {
      try {
        (ldapAuth.principals.map {
          case LdapKnownPrincipal(principal) =>
            (Some(principal.replace("HUMIOUSERNAME", username)), None)
          case LdapPrincipalSearch(searchBindName, searchBindNamePassword, dn, filter, transformUsernameToPrincipal) =>
            val env = ldapEnv(url, searchBindName, searchBindNamePassword, ldapAuth.conn.env())
            val searchControls = new SearchControls()
            searchControls.setReturningAttributes(
              usernameAttribute match {
                case Some(attribute) => Array("dn", "distinguishedName", "userPrincipalName", attribute)
                case None => Array("dn", "distinguishedName", "userPrincipalName")
              })
            searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE)
            val args: Array[AnyRef] = Seq(transformUsernameToPrincipal(username)).toArray
            try {
              logger.debug(s"initial dir context env=$env")
              val searchCtx = new InitialDirContext(env)
              try {
                logger.debug(s"search: base=$dn filter=$filter args=${args.mkString("[", ", ", "]")}")
                val (name, humioUsername) = searchCtx.search(dn, filter, args, searchControls).asScala.collect {
                  case result =>
                    (Option(result.getNameInNamespace), usernameAttribute match {
                      case Some(attribute) =>
                        Try(result.getAttributes.get(attribute).get().asInstanceOf[String]).collect {
                          case attrValue =>
                            logger.debug(s"ldap search username attribute $attribute=$attrValue")
                            attrValue
                        }.toOption
                      case None => Option(result.getNameInNamespace)
                    })
                }.next
                logger.debug(s"searching for username=$username in dn=$dn filter=$filter produced name=$name humioUsername=$humioUsername")
                (name, humioUsername)
              } finally {
                searchCtx.close()
              }
            } catch {
              case e: NamingException =>
                // We may try many different combinations when searching so we expect some to fail.
                logger.debug(s"rejected dn=$dn filter=$filter args=${args.mkString("[", ", ", "]")} reason=${e.getMessage}")
                (None, Option.empty[String])
            }
        } collectFirst {
          case (Some(dn), humioUsername) if {
            try {
              val env = ldapEnv(url, dn, password, ldapAuth.conn.env())
              ctx = new InitialDirContext(env)
              true
            } catch {
              case e: javax.naming.AuthenticationException =>
                logger.warn(s"login as username=$username dn=$dn rejected: $e")
                false
              case ExceptionUtils.NonFatal(e) =>
                logger.warn(s"login as username=$username dn=$dn failed: $e")
                false
            }
          } => Some((ctx, dn, humioUsername))
        } collect {
          case Some((ctx: InitialDirContext, dn: String, humioUsername)) =>
            logger.debug(s"login as username=$username dn=$dn succeeded")
            if (true) { // (config.autoUpdateGroupMembershipsOnSuccessfullLogin) {
              val groupBaseDn = ldapGroupBaseDn.getOrElse(dn)
              logger.debug(s"searching for group memberships within ldap for username=$username dn=$dn within groupBaseDn=$groupBaseDn")
              val filter = ldapGroupFilter.getOrElse("(& (objectClass=group) (member:1.2.840.113556.1.4.1941:={0}))")
              val groupLookups = Seq(LdapGroupLookup(groupBaseDn, filter))
              val searchControls = new javax.naming.directory.SearchControls()
              searchControls.setReturningAttributes(
                groupnameAttribute match {
                  case Some(attribute) => Array("dn", "distinguishedName", attribute)
                  case None => Array("dn", "distinguishedName")
                })
              searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE)
              val args: Array[AnyRef] = Seq(dn).toArray
              groupLookups collectFirst {
                case LdapGroupLookup(groupDn, filter) =>
                  logger.debug(s"searching for the username=$username (dn=$dn) within the groups in groupDn=$groupDn filter=$filter args=${args.mkString("[", ", ", "]")}")
                  try {
                    ctx.search(groupDn, filter, args, searchControls).asScala.collect {
                      case result =>
                        groupnameAttribute match {
                          case Some(attribute) =>
                            Try(result.getAttributes.get(attribute).get().asInstanceOf[String]).collect {
                              case name =>
                                logger.debug(s"ldap search groupname attribute $attribute=$name")
                                name
                            }.toOption match {
                              case Some(group) => Seq(group, result.getNameInNamespace)
                              case None => Seq(result.getNameInNamespace)
                            }
                          case None => Seq(result.getNameInNamespace)
                        }
                    }.toSeq.flatten
                  } catch {
                    case e: javax.naming.directory.InvalidSearchFilterException if !ctx.getEnvironment.containsKey("java.naming.ldap.version") =>
                      logger.warn(s"group search failed ${e.getMessage}, try setting LDAP_PROTOCOL_VERSION=3 in your config if you are using ActiveDirectory", e)
                      Seq.empty[String]
                    case ExceptionUtils.NonFatal(e) =>
                      logger.warn(s"group search groupDn=$groupDn filter=$filter args=${args.mkString("[", ", ", "]")} failed, ${e.getMessage}", e)
                      Seq.empty[String]
                  }
              } match {
                case Some(groups) if groups.nonEmpty =>
                  logger.debug(s"username=$username dn=$dn is a member of ${groups.length} groups=${groups.mkString("[", ", ", "]")}")
                  // We've discovered a set of groups associated with this authenticated user, return their dn/groups.
                  (Some(dn), humioUsername, groups)
                case _ =>
                  logger.debug(s"username=$username dn=$dn was not associated with any groups")
                  // We've found that this user has no groups, or we couldn't find them but they are authenticated so return their dn.
                  (Some(dn), humioUsername, Seq.empty[String])
              }
            } else {
              // Humio wasn't configured to update groups on successful login so we don't look for group membership.  The user has been authenticated, so just return that.
              (Some(dn), humioUsername, Seq.empty[String])
            }
        })
          // User couldn't be authenticated using provided information when this statement results in `None`.
          .getOrElse((None, None, Seq.empty[String]))
      } finally {
        if (ctx != null)
          ctx.close()
      }
    } else {
      logger.warn(s"authentication failed, unable to connect to LDAP server url=$url")
      (None, None, Seq.empty[String])
    }
  }

  private def getPrincipalName(username: String, domainName: String): String = {
    val slash = username.indexOf('\\')
    if (slash >= 0) {
      username.substring(slash + 1) + '@' + domainName
    } else if (username.contains("@")) {
      username
    } else {
      if (domainName.isBlank)
        username
      else
        username + '@' + domainName
      }
  }

  //  private def ldapConfigFromEnv(kind: AuthenticationMethod.Value): Option[LdapAuthConfig] = {
  private def ldapConfigFromEnv(): Option[LdapAuthConfig] = {
    def trimDoubleQuotes(text: Option[String]): Option[String] = text match {
      case Some(text) =>
        val textLength = text.length
        if (textLength >= 2 && text.charAt(0) == '"' && text.charAt(textLength - 1) == '"')
          Some(text.substring(1, textLength - 1)) else Some(text)
      case None =>
        None
    }

    def envget(key: String): Option[String] = trimDoubleQuotes(sys.env.get(key))

      Some(LdapAuthConfig(
        ldapDomainName = envget("LDAP_DOMAIN_NAME"),
        ldapAuthProviderUrl = envget("LDAP_AUTH_PROVIDER_URL"),
        ldapAuthProviderCert = envget("LDAP_AUTH_PROVIDER_CERT"),
        ldapAuthPrincipal = envget("LDAP_AUTH_PRINCIPAL"),
        ldapAuthPrincipalsRegex = envget("LDAP_AUTH_PRINCIPALS_REGEX"),
        ldapSearchBindName = envget("LDAP_SEARCH_BIND_NAME"),
        ldapSearchBindPassword = envget("LDAP_SEARCH_BIND_PASSWORD"),
        ldapSearchDomainName = envget("LDAP_SEARCH_DOMAIN_NAME"),
        ldapSearchBaseDn = envget("LDAP_SEARCH_BASE_DN"),
        ldapSearchFilter = envget("LDAP_SEARCH_FILTER"),
        ldapGroupBaseDn = envget("LDAP_GROUP_BASE_DN"),
        ldapGroupFilter = envget("LDAP_GROUP_FILTER")))
    }

}

object Main {

  val logger = Logger.forObject(this)

  def main(args: Array[String]): Unit = {

    if (args.length < 2) {
      logger.info(
        s"""
           |Usage: java -jar ldap-test.jar <username> <password>
           |    environment variable     =>     example value
           |    AUTHENTICATION_METHOD           ldap|ldap-search
           |    LDAP_DOMAIN_NAME                example.com
           |    LDAP_AUTH_PROVIDER_URL          ldap://ldap.example.com or ldaps: for TLS
           |    LDAP_AUTH_PROVIDER_CERT         LDAP_AUTH_PROVIDER_CERT=-----BEGIN CERTIFICATE-----\\nMII...gWc=\\n-----END CERTIFICATE-----\\n
           |    LDAP_AUTH_PRINCIPAL             cn=HUMIOUSERNAME,dc=example,dc=com;cn=HUMIOUSERNAME,dc=foo,dc=bar
           |    LDAP_AUTH_PRINCIPALS_REGEX      ;
           |    LDAP_SEARCH_BIND_NAME           cn=Bind User,dc=example,dc=com
           |    LDAP_SEARCH_BIND_PASSWORD       sekret,pa55w0rd!
           |    LDAP_SEARCH_DOMAIN_NAME         example.com
           |    LDAP_SEARCH_BASE_DN             ou=DevOps,dc=example,dc=com
           |    LDAP_SEARCH_FILTER              (& (userPrincipalName={0})(objectCategory=user))
           |    LDAP_GROUP_BASE_DN              ou=User administration,dc=example,dc=com
           |    LDAP_GROUP_FILTER               (& (objectClass=group) (member:1.2.840.113556.1.4.1941:={0}))
           |
           |    Phase 1: Determine DN we need to authenticate.  When not using LdapSearch this is constructed from the
           |    login username and the LDAP_AUTH_PRINCIPAL(s).  Each one is tried in turn combined with the password.
           |    When LdapSearch is used there is a phase before this.
           |
           |    Phase 0.5: LDAP search is used to find the DN for the user by first logging into the LDAP server with
           |    a well known LDAP_SEARCH_BIND_NAME/PASSWORD.  The goal is to find the DN for the login user within
           |    the LDAP directory server, then authenticate that against the password provided.
           |
           |    Phase 2: Assuming the DN/password authenticated next up is determining if the user belongs to any
           |    groups.  The group membership is used for RBAC.
           |
           |    Requires Java 11 or later.tig
         """.stripMargin)
    } else {
      logger.info(s"Testing LDAP login for user=${args(0)}")

      if (LdapBindLocalLogin.login(args(0), args(1))) {
        logger.info(s"Fantastic, that seems to have worked.")
      } else {
        logger.info(s"Things didn't go as planned, keep trying!")
      }
    }
  }

}

object ExceptionUtils {

  private val logger = Logger.forObject(this)

  /** Defines what fatal means in our system! */
  def isFatal(t: Throwable) = t match {
    case _: StackOverflowError => false // We can recover from StackOverflowError even though it is a subclass of VirtualMachineError
    case _: Error => true
    case _ => false
  }

  def isNonFatal(t: Throwable) = !isFatal(t)

  object Fatal {
    /**
     * Extractor for matching all fatal throwables.
     * Fatal throwables are things that should result in JVM shutdown
     */
    def unapply(t: Throwable): Option[Throwable] = if (isFatal(t)) Some(t) else None
  }

  object NonFatal {
    /**
     * Extractor for matching all throwables that are non-fatal, meaning the JVM is in a sound state.
     * (In a fatal situation the JVM should be shutdown immediately).
     */
    def unapply(t: Throwable): Option[Throwable] = if (isNonFatal(t)) Some(t) else None
  }
}

object Logger {
  def forObject(o: Any): ch.qos.logback.classic.Logger = {
    buildLogger(o.getClass.getCanonicalName)
  }

  def buildLogger(string: String, file: Option[String] = None): ch.qos.logback.classic.Logger = {
    val ple = new PatternLayoutEncoder()
    val lc = LoggerFactory.getILoggerFactory.asInstanceOf[LoggerContext]
    ple.setPattern("%date %level [%thread] %logger{10} [%file:%line]\t%msg%n")
    ple.setContext(lc)
    ple.start()

    val appender = /*file match {
      case Some(path) =>
        val fileAppender = new FileAppender[IloggingEvent]()
        fileAppender.setFile(path)
        fileAppender
      case None => */
      new ConsoleAppender[ILoggingEvent]()
    //}
    appender.setEncoder(ple)
    appender.setContext(lc)
    appender.start()

    // org.slf4j.Logger.ROOT_LOGGER_NAME
    val logger = LoggerFactory.getLogger(string).asInstanceOf[ch.qos.logback.classic.Logger]
    logger.addAppender(appender)
    logger.setLevel(Level.ALL)
    logger.setAdditive(false)

    logger
  }
}

class HumioException(msg: String) extends Exception

object LocalLogin {
  val loginFailure = false
}

case class AuthProviderProfile(
  provider: String,
  authProviderUsername: String,
  humioUsername: String,
  email: Option[Option[String]] = None,
  company: Option[Option[String]] = None,
  location: Option[Option[String]] = None,
  name: Option[Option[String]] = None,
  isRoot: Option[Option[Boolean]] = None,
  picture: Option[Option[String]] = None)

object AuthenticationMethod extends Enumeration {
  val NoAuthentication, SingleUser, Auth0, Ldap, LdapSearch, Static, SetByProxy, FederatedIdentity, OAuth, SAML = Value
}

case class LdapAuthConfig
( ldapAuthProviderUrl: Option[String],
  ldapAuthProviderCert: Option[String],
  ldapDomainName: Option[String],
  ldapAuthPrincipal: Option[String],
  ldapAuthPrincipalsRegex: Option[String],
  ldapSearchBindName: Option[String],
  ldapSearchBindPassword: Option[String],
  ldapSearchBaseDn: Option[String],
  ldapSearchDomainName: Option[String],
  ldapSearchFilter: Option[String],
  ldapGroupBaseDn: Option[String],
  ldapGroupFilter: Option[String])

