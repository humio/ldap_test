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

case class LdapAuthConfig(
  ldapAuthProviderUrl: Option[String],
  ldapAuthProviderCert: Option[String],
  ldapDomainName: Option[String],
  ldapAuthPrincipal: Option[String],
  ldapAuthPrincipalsRegex: Option[String],
  ldapSearchBindName: Option[String],
  ldapSearchBindPassword: Option[String],
  ldapSearchBaseDN: Option[String],
  ldapSearchDomainName: Option[String],
  ldapSearchFilter: Option[String],
  ldapGroupBaseDN: Option[String],
  ldapGroupFilter: Option[String])

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
  require(url.startsWith("ldaps:"), "The LDAPS (LDAP over TLS) endpoint must begin with 'ldaps:' not " + url.take(6))

  override def env(): Map[String, String] = {
    super.env ++
    Map(
      javax.naming.Context.SECURITY_PROTOCOL -> Option("ssl"),
      cert match {
        case None => "" -> None
        case Some(c) => {
          SelfSignedSSLSocketFactory.setCertificate(c)
          "java.naming.ldap.factory.socket" -> Option(SelfSignedSSLSocketFactory.name())
        }
      }
    ).filter(_._2.isDefined).mapValues(_.get)
  }
}

object LocalLogin {
  val loginFailure = false
}

sealed abstract class LdapPrincipalLookup
case class LdapNamedPrincipal(domain: String, principal: String) extends LdapPrincipalLookup
case class LdapPrincipalSearch(username: String, password: String, dn: String, filter: String) extends LdapPrincipalLookup

case class LdapAuth(conn: LdapConnectionMethod, principals: Seq[LdapPrincipalLookup])

case class LdapGroupLookup(dn: String, filter: String)

object Main {

  val logger = createLoggerFor("ldap-test")

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

      if (login(args(0), args(1))) {
        logger.info(s"Fantastic, that seems to have worked.")
      } else {
        logger.info(s"Things didn't go as planned, keep trying!")
      }
    }
  }

//  private def ldapConfigFromEnv(kind: AuthenticationMethod.Value): Option[LdapAuthConfig] = {
  private def ldapConfigFromEnv(): Option[LdapAuthConfig] = {
    Some(LdapAuthConfig(
      ldapDomainName = sys.env.get("LDAP_DOMAIN_NAME"),
      ldapAuthProviderUrl = sys.env.get("LDAP_AUTH_PROVIDER_URL"),
      ldapAuthProviderCert = sys.env.get("LDAP_AUTH_PROVIDER_CERT"),
      ldapAuthPrincipal = sys.env.get("LDAP_AUTH_PRINCIPAL"),
      ldapAuthPrincipalsRegex = sys.env.get("LDAP_AUTH_PRINCIPALS_REGEX"),
      ldapSearchBindName = sys.env.get("LDAP_SEARCH_BIND_NAME"),
      ldapSearchBindPassword = sys.env.get("LDAP_SEARCH_BIND_PASSWORD"),
      ldapSearchDomainName = sys.env.get("LDAP_SEARCH_DOMAIN_NAME"),
      ldapSearchBaseDN = sys.env.get("LDAP_SEARCH_BASE_DN"),
      ldapSearchFilter = sys.env.get("LDAP_SEARCH_FILTER"),
      ldapGroupBaseDN = sys.env.get("LDAP_GROUP_BASE_DN"),
      ldapGroupFilter = sys.env.get("LDAP_GROUP_FILTER")))
  }

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
          logger.error(s"This tool tests LDAP authentication, not ${method}.")
          AuthenticationMethod.NoAuthentication
        case None =>
          logger.error(s"Missing environment variable AUTHENTICATION_METHOD")
          AuthenticationMethod.NoAuthentication
      }
      val ldapConfig = ldapConfigFromEnv()
      logger.info(s"ldapAuthConfig=${ldapConfig}")
      ldapConfig match {
        case None => LocalLogin.loginFailure
        case Some(ldapAuthConfig) => {
          if (username.isBlank) {
            logger.info(s"missing username in login request")
            LocalLogin.loginFailure
          } else if (pass.isBlank) {
            logger.info(s"missing password in login request")
            LocalLogin.loginFailure
          } else {
            val domain = ldapAuthConfig.ldapDomainName.getOrElse("")
            val principalName = getPrincipalName(username, domain)
            val ldapAuth = ldapAuthFromConfig(authenticationMethod, domain, ldapAuthConfig)
            val profile = AuthProviderProfile(provider = "Static", authProviderUsername = principalName, humioUsername = principalName, email = None)
            openLdapContext(username, pass, ldapAuthConfig.ldapAuthProviderUrl.get, ldapAuth, ldapAuthConfig.ldapGroupBaseDN, ldapAuthConfig.ldapGroupFilter) match {
              case (Some(_), groups) => true //loginService.login(profile, optionals, groups)
              case _ => LocalLogin.loginFailure
            }
          }
        }
      }
    }
  }

  private def ldapAuthFromConfig(kind: AuthenticationMethod.Value, domain: String, ldapAuthConfig: LdapAuthConfig): LdapAuth = {
    val splitPrincipals = ldapAuthConfig.ldapAuthPrincipalsRegex
    val uri = ldapAuthConfig.ldapAuthProviderUrl
    LdapAuth(
      uri match {
        case Some(url) if url.startsWith("ldap:") => UnsecuredLdapConnection(url)
        case Some(url) if url.startsWith("ldaps:") => SecuredLdapConnection(url, ldapAuthConfig.ldapAuthProviderCert)
        case None => throw new Exception(s"The LDAP authentication URL is missing or incorrect. LDAP_AUTH_PROVIDER_URL=${uri}")
      },
      (ldapAuthConfig.ldapAuthPrincipal match {
        case Some(principals) if principals.nonEmpty && splitPrincipals.isDefined =>
          principals.split(splitPrincipals.get).toSeq
        case Some(principal) if principal.nonEmpty =>
          Seq(principal)
        case _ => Seq.empty
      }).map(principal => LdapNamedPrincipal(domain, principal)) ++
        (kind match {
          case AuthenticationMethod.LdapSearch =>
            (ldapAuthConfig.ldapSearchBindName, ldapAuthConfig.ldapSearchBindPassword, ldapAuthConfig.ldapSearchBaseDN) match {
              case (Some(name), Some(pass), Some(dn)) =>
                ldapAuthConfig.ldapSearchFilter match {
                  case None =>
                    val principalName = getPrincipalName(name, ldapAuthConfig.ldapSearchDomainName.get)
                    Seq(
                      LdapPrincipalSearch(principalName, pass, dn, "(& (userPrincipalName={0})(objectCategory=user))"),
                      LdapPrincipalSearch(principalName.substring(0, principalName.indexOf('@')), pass, dn, "(& (sAMAccountName={0})(objectCategory=user))"))
                  case Some(filter) =>
                    Seq(LdapPrincipalSearch(name, pass, dn, filter))
                }
              case _ =>
                logger.error(s"Missing information required to perform ldap-search. LDAP_SEARCH_BIND_NAME=${ldapAuthConfig.ldapSearchBindName} LDAP_SEARCH_BIND_PASSWORD=${if (ldapAuthConfig.ldapSearchBindPassword.isEmpty) "empty" else "redacted"} LDAP_SEARCH_BASE_DN=${ldapAuthConfig.ldapSearchBaseDN}")
                Seq.empty
            }
          case _ => Seq.empty
        }))
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

  private def openLdapContext(username: String, password: String, url: String, ldapAuth: LdapAuth, ldapGroupBaseDN: Option[String], ldapGroupFilter: Option[String]): (Option[String], Seq[String])= {
    logger.info(s"ldap login for user=${username} starting...")
    var ctx: InitialDirContext = null

    (ldapAuth.principals.map(_ match {
      case LdapNamedPrincipal(_, principal) =>
        Some(principal.replace("HUMIOUSERNAME", username))
      case search: LdapPrincipalSearch =>
        try {
          val controls = new SearchControls()
          controls.setSearchScope(SearchControls.SUBTREE_SCOPE)
          val args: Array[AnyRef] = Seq(search.username).toArray
          val ctx = new InitialDirContext(ldapEnv(url, search.dn, search.password, ldapAuth.conn.env))
          try {
            logger.info(s"search: base=${search.dn} filter=${search.filter} args=${args.toList}")
            val r = ctx.search(search.dn, search.filter, args, controls)
            if (r.hasMore) {
              val searchResult = r.next
              val dn = searchResult.getNameInNamespace
              logger.info(s"searching for user=${search.username} in dn=${search.dn} filter=${search.filter} got name=$dn")
              Some(dn)
            } else {
              None
            }
          } finally {
            ctx.close()
          }
        } catch {
          case e: NamingException =>
            // We may try many different combinations when searching so we expect some to fail.
            logger.info(s"rejected dn=${search.dn} filter=${search.filter} args=${search.username} reason=${e.getMessage}")
            None
        }
    }) collectFirst {
      case Some(dn) if {
        try {
          ctx = new InitialDirContext(ldapEnv(url, dn, password, ldapAuth.conn.env))
          true
        } catch {
          case e: javax.naming.AuthenticationException =>
            logger.info(s"login as user=${username} dn=${dn} rejected: ${e}")
            false
          case e: Throwable =>
            logger.warn(s"authentication failed: ${e}")
            rethrowIfFatal(e)
            false
        }
      } => Some((ctx, dn))
    } collect {
      case Some((ctx: InitialDirContext, dn: String)) =>
        logger.info(s"login as user=${username} dn=${dn} succeeded")
        if (ldapGroupBaseDN.isDefined) {
          val groupInfo = LdapGroupLookup(ldapGroupBaseDN.get, ldapGroupFilter.getOrElse("(& (objectClass=group) (member:1.2.840.113556.1.4.1941:={0}))"))
          val sc = new javax.naming.directory.SearchControls()
          sc.setSearchScope(SearchControls.SUBTREE_SCOPE)
          val args: Array[AnyRef] = Seq(dn).toArray
          logger.info(s"searching for the user=${username} groups within dn=${groupInfo.dn} using filter=${groupInfo.filter} and args=${args}")
          val groups = ctx.search(groupInfo.dn, groupInfo.filter, args, sc).asScala.collect { case group => group.getNameInNamespace }.toSeq
          if (groups.nonEmpty)
            logger.info(s"dn=${dn} is a member of groups=${groups}")
          (Some(dn), groups)
        } else {
          (Some(dn), Seq.empty[String])
        }
    }).getOrElse((None, Seq.empty[String]))
  }

  private def getPrincipalName(username: String, domainName: String): String = {
    val slash = username.indexOf('\\')
    val principalName =
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
    principalName
  }

  def rethrowIfFatal(e: Throwable): Unit = {
    e match {
      case e: Error => throw e
      // Other cases that need rethrow to start shutdown in particular?
      case _ => //fine.
    }
  }

  def createLoggerFor(string: String, file: Option[String] = None): ch.qos.logback.classic.Logger = {
    val ple = new PatternLayoutEncoder()
    val lc = LoggerFactory.getILoggerFactory().asInstanceOf[LoggerContext]
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
    logger.setLevel(Level.DEBUG)
    logger.setAdditive(false)

    logger
  }

}