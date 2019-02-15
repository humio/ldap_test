package com.humio.ldap_test

import java.util

import ch.qos.logback.classic.{ Level, Logger, LoggerContext }
import ch.qos.logback.classic.encoder.PatternLayoutEncoder
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.core.{ ConsoleAppender, FileAppender }
import com.sun.jndi.ldap.LdapCtxFactory

import collection.JavaConverters._
import javax.naming.directory._
import org.slf4j.LoggerFactory

object AuthenticationMethod extends Enumeration {
  val NoAuthentication, SingleUser, Auth0, Ldap, LdapSearch, Static, SetByProxy, FederatedIdentity, OAuth, SAML = Value
}

case class LdapAuthConfig(ldapDomainName: Option[String], ldapLoginPattern: Option[String], ldapSearchBaseDN: Option[String],
  base_env: Map[String, String], ldapAuthPrincipal: Option[String],
  ldapSearchBindName: Option[String], ldapSearchBindPassword: Option[String], ldapSearchFilter: Option[String],
  ldapGroupBaseDN: Option[String], ldapGroupFilter: Option[String])

object Main {

  val logger = createLoggerFor("ldap-test")

  def main(args: Array[String]): Unit = {

    logger.info(s"logging in with user=${args(0)}, pass=${args(1)}")

    if (login(args(0), args(1))) {
      logger.info(s"Fantastic, that seems to have worked.")
    } else {
      logger.info(s"Things didn't go as planned, keep trying!")
    }
  }

  val kind = sys.env.get("AUTHENTICATION_METHOD") match {
    case Some("ldap") => AuthenticationMethod.Ldap
    case Some("ldap-search") => AuthenticationMethod.LdapSearch
    case other =>
      logger.info(s"""unknown/supported authentication kind "${other}", using "ldap-search" """)
      AuthenticationMethod.LdapSearch
  }

  val conf = ldapConfigFromEnv(kind) match {
    case None =>
      throw new RuntimeException("ldap provider url is required for ldap auth.")
    case Some(cfg) =>
      cfg
  }

  private def ldapConfigFromEnv(kind: AuthenticationMethod.Value): Option[LdapAuthConfig] = {
    val ldapAuthProviderUrl = sys.env.get("LDAP_AUTH_PROVIDER_URL")
    if (ldapAuthProviderUrl.nonEmpty) {
      var env = Map[String, String]()
      env += javax.naming.Context.PROVIDER_URL -> ldapAuthProviderUrl.get
      if (ldapAuthProviderUrl.get.startsWith("ldaps:")) {
        env += javax.naming.Context.SECURITY_PROTOCOL -> "ssl"

        val ldapCert = sys.env.get("LDAP_AUTH_PROVIDER_CERT")

        if (ldapCert.nonEmpty) {
          SelfSignedSSLSocketFactory.setCertificate(ldapCert.get)
          env += "java.naming.ldap.factory.socket" -> SelfSignedSSLSocketFactory.name()
        }

      }
      env += javax.naming.Context.INITIAL_CONTEXT_FACTORY -> classOf[LdapCtxFactory].getName
      env += javax.naming.Context.SECURITY_AUTHENTICATION -> "simple"

      val ldapDomainName = sys.env.get("LDAP_DOMAIN_NAME").orElse(env.get("LDAP_SEARCH_DOMAIN_NAME"))
      val ldapLoginPattern = sys.env.get("LDAP_LOGIN_PATTERN")
      val ldapGroupBaseDN = sys.env.get("LDAP_GROUP_BASE_DN")
      val ldapGroupFilter = sys.env.get("LDAP_GROUP_FILTER")
      val ldapAuthPrincipal = sys.env.get("LDAP_AUTH_PRINCIPAL")
      kind match {
        case AuthenticationMethod.Ldap =>
          logger.info("authentication method: ldap")
          Some(LdapAuthConfig(ldapDomainName = ldapDomainName, ldapLoginPattern = ldapLoginPattern, ldapSearchBaseDN = None, base_env = env, ldapAuthPrincipal = ldapAuthPrincipal, ldapSearchBindName = None, ldapSearchBindPassword = None, ldapSearchFilter = None, ldapGroupBaseDN = ldapGroupBaseDN, ldapGroupFilter = ldapGroupFilter))

        case AuthenticationMethod.LdapSearch =>
          logger.info("authentication method: ldap-search")
          val slashIdx = ldapAuthProviderUrl.get.indexOf("/")
          val baseFromUrl = if (slashIdx > 0) {
            ldapAuthProviderUrl.get.substring(slashIdx)
          } else {
            ""
          }
          val ldapSearchBindName = sys.env.get("LDAP_SEARCH_BIND_NAME")
          val ldapSearchBindPassword = sys.env.get("LDAP_SEARCH_BIND_PASSWORD")
          val ldapSearchBaseDN = sys.env.getOrElse("LDAP_SEARCH_BASE_DN", baseFromUrl)
          val ldapSearchFilter = sys.env.get("LDAP_SEARCH_FILTER")
          Some(LdapAuthConfig(ldapDomainName = ldapDomainName, ldapLoginPattern = ldapLoginPattern, ldapSearchBaseDN = Some(ldapSearchBaseDN), base_env = env, ldapAuthPrincipal = None, ldapSearchBindName = ldapSearchBindName, ldapSearchBindPassword = ldapSearchBindPassword, ldapSearchFilter = ldapSearchFilter, ldapGroupBaseDN = ldapGroupBaseDN, ldapGroupFilter = ldapGroupFilter))
        case _ =>
          None
      }
    } else {
      logger.info("no LDAP_AUTH_PROVIDER_URL")
      None
    }
  }

  private def ldapEnv(dn: String, secret: String) = {
    logger.info(s"ldap env dn=${dn}; hash(secret)=${secret.hashCode}")
    var env = conf.base_env
    env += javax.naming.Context.SECURITY_PRINCIPAL -> dn
    env += javax.naming.Context.SECURITY_CREDENTIALS -> secret
    val hashTable = new util.Hashtable[String, String]()
    hashTable.putAll(env.asJava)
    hashTable
  }

  private def searchStep(username: String): Option[String] = {
    val baseDN: String = conf.ldapSearchBaseDN.getOrElse("")

    def searchOne(filter: String, arg: String): Option[String] = {
      try {
        val controls = new SearchControls()
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE)
        val env = ldapEnv(conf.ldapSearchBindName.get, conf.ldapSearchBindPassword.get)
        val args: Array[AnyRef] = Seq(arg).toArray
        val ctx = new InitialDirContext(env)
        try {
          logger.info(s"ldap search: base=${baseDN}; filter=${filter}; args=${args.toList}")

          val r = ctx.search(baseDN, filter, args, controls)
          if (r.hasMore) {
            val searchResult = r.next
            val attrs = searchResult.getAttributes
            val name = searchResult.getNameInNamespace
            logger.info(s"ldap searching for arg=${arg} in ldapSearchBaseDN=${baseDN} with filter=${filter} got name=${name}")
            Some(name)
          } else {
            None
          }
        } finally {
          ctx.close()
        }
      } catch {
        case e: Exception =>
          // We try two different methods when searching, frequently one fails.  Writing warnings to the
          // log with exception only confuses people.
          logger.info(s"ldap searching as user=${conf.ldapSearchBindName.get} was rejected.")
          None
      }
    }

    val userPrincipalName = getPrincipalName(username, conf)
    val samAccountName = userPrincipalName.substring(0, userPrincipalName.indexOf('@'))
    if (conf.ldapSearchFilter.nonEmpty) {
      val filter: String = conf.ldapSearchFilter.get
      searchOne(filter, userPrincipalName)
    } else {
      val filter1: String = "(& (userPrincipalName={0})(objectCategory=user))"
      val filter2: String = "(& (sAMAccountName={0})(objectCategory=user))"
      searchOne(filter1, userPrincipalName) match {
        case Some(s) => Some(s)
        case None => searchOne(filter2, samAccountName)
      }
    }
  }

  /*
    override def login(username: String, pass: String, optionals: RequestOptionals): Try[String] = {
    if (check(username, pass)) {
      val profile = AuthProviderProfile(provider = "Static", authProviderUsername = getPrincipalName(username, conf), humioUsername = username, email = None)
      val groups = if (config.autoUpdateGroupMembershipsOnSuccessfullLogin) {
        groupsForUser(username, pass).getOrElse(Set()).toSeq
      } else {
        Seq()
      }
      loginService.login(profile, optionals, groups)
    } else {
      LocalLogin.loginFailure
    }
  }
  */

  def login(username: String, pass: String): Boolean = {
    if (check(username, pass)) {
      logger.info("login succeeded")
      groupsForUser(username, pass) match {
        case None =>
          logger.info("no groups found")
          false
        case Some(set) =>
          logger.info(s"groups found: ${set.size}")
          for (g <- set) {
            logger.info("\"" + g + "\"")
          }
          true
      }
    } else {
      false
    }
  }

  private def check(username: String, secret: String): Boolean = {
    logger.info(s"ldap login for user=${username} starting...")

    val (dn, searchAfterBind) = if (conf.ldapSearchBindName.nonEmpty) {
      // We must bind using ldapSearchBindName/pass to search for the user, then use the DN we find in the actual login.
      (searchStep(username), true)
    } else {
      // Direct bind using provided input from user:
      conf.ldapAuthPrincipal match {
        case Some(s) =>
          (Some(s.replace("HUMIOUSERNAME", username)), false)
        case _ =>
          (Some(getPrincipalName(username, conf)), false)
      }
    }

    logger.info(s"check() initial dir context dn=${dn}")
    if (dn.nonEmpty) {
      try {
        val env = ldapEnv(dn.get, secret)
        val ctx = new InitialDirContext(env)
        try {
          if (searchAfterBind) {
            // Try a search - it throws if we are not properly logged in.
            val baseDN = dn.get
            val filter = "(& (dn={0})(objectCategory=user))"
            val args = Seq(dn.get).toArray[AnyRef]
            logger.info(s"ldap search: base=${baseDN}; filter=${filter}; args=${args.toList}")
            ctx.search(baseDN, filter, args, new SearchControls())
          }
        } finally {
          ctx.close()
        }
        logger.info(s"ldap login as user=${username} dn=${dn} succeeded.")
        true
      } catch {
        case e: javax.naming.AuthenticationException =>
          logger.info(s"ldap login as user=${username} dn=${dn} rejected.", e)
          false
        case e: Throwable =>
          logger.warn("ldap authentication failed", e)
          false
      }
    } else {
      logger.info(s"ldap login as user=${username} dn=${dn} not tried as DN was not found")
      false
    }
  }

  def groupsForUser(username: String, secret: String): Option[Set[String]] = {

    val dn = if (conf.ldapSearchBindName.nonEmpty) {
      // We must bind using ldapSearchBindName/pass to search for the user, then use the DN we find in the actual login.
      searchStep(username)
    } else {
      // Direct bind using provided input from user:
      Option(conf.ldapAuthPrincipal match {
        case Some(s) =>
          s.replace("HUMIOUSERNAME", username)
        case _ =>
          getPrincipalName(username, conf)
      })
    }
    logger.info(s"groupsForUser() dn=${dn}")

    if (dn.isEmpty) {
      None
    } else {

      var groups = Set[String]()

      try {
        val env = ldapEnv(dn.get, secret)
        val ctx = new InitialDirContext(env)
        try {

          val groupFilter = conf.ldapGroupFilter.getOrElse("(& (objectClass=group) (member:1.2.840.113556.1.4.1941:={0}))")
          val groupBaseDN = conf.ldapGroupBaseDN.getOrElse(dn.get)
          val searchGroupSubtree = true

          import javax.naming.directory.SearchControls
          val sc = new SearchControls
          if (searchGroupSubtree)
            sc.setSearchScope(SearchControls.SUBTREE_SCOPE)

          val args = Seq(dn.get).toArray[AnyRef]
          logger.info(s"ldap search: base=${groupBaseDN}; filter=${groupFilter}; args=${args.toList}")

          val answer = ctx.search(groupBaseDN, groupFilter, args, sc)

          while (answer.hasMore) {
            val sr = answer.next
            val name = sr.getNameInNamespace
            logger.debug("*** Inspecting group \"" + name + "\" for user " + username)
            groups = groups + name
          }

        } finally {
          ctx.close()
        }
        logger.info(s"ldap login as user=${username} dn=${dn} succeeded.")
        Some(groups)

      } catch {
        case e: javax.naming.AuthenticationException =>
          logger.info(s"ldap login as user=${username} dn=${dn} rejected.", e)
          None
        case e: Throwable =>
          logger.warn("ldap authentication failed", e)
          None
      }
    }
  }

  private def getPrincipalName(username: String, conf: LdapAuthConfig): String = {
    val domainName = conf.ldapDomainName.getOrElse("")
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
    logger.info(s"username=${username} domainName=${conf.ldapDomainName} principalName=${principalName}")
    principalName
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

