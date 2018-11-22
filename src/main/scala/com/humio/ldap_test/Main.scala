package com.humio.ldap_test

import java.util
import java.util.logging.{ConsoleHandler, Level, Logger}

import com.sun.jndi.ldap.LdapCtxFactory

import collection.JavaConverters._
import javax.naming.directory._

object AuthenticationMethod extends Enumeration {
  val NoAuthentication, SingleUser, Auth0, Ldap, LdapSearch, Static, SetByProxy, FederatedIdentity, OAuth, SAML = Value
}

case class LdapAuthConfig(domainName: Option[String], baseDN: Option[String],
                          base_env: Map[String, String], ldapAuthPrincipal: Option[String],
                          bindName: Option[String], bindPassword: Option[String], bindFilterString: Option[String],
                          groupDN: Option[String], groupFilter: Option[String]
                         )

object Main {

  val logger = Logger.getLogger(this.getClass.getName)
  // logger.addHandler( new ConsoleHandler() )

  def main(args: Array[String]): Unit = {

    println(s"logging in with user=${args(0)}, pass=${args(1)}")

    login(args(0), args(1))

  }

  val conf = ldapConfigFromEnv(AuthenticationMethod.LdapSearch) match {
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
      env += javax.naming.Context.INITIAL_CONTEXT_FACTORY ->  classOf[LdapCtxFactory].getName
      env += javax.naming.Context.SECURITY_AUTHENTICATION -> "simple"


      val ldapGroupBaseDN = sys.env.get("LDAP_GROUP_BASE_DN")
      val ldapGroupFilter = sys.env.get("LDAP_GROUP_FILTER")

      kind match {
        case AuthenticationMethod.Ldap =>
          val ldapAuthPrincipal = sys.env.get("LDAP_AUTH_PRINCIPAL")
          val ldapDomainName = sys.env.get("LDAP_DOMAIN_NAME")
          Some(LdapAuthConfig(domainName = ldapDomainName, baseDN = None, base_env = env, ldapAuthPrincipal = ldapAuthPrincipal, bindName = None, bindPassword = None, bindFilterString = None, groupDN = ldapGroupBaseDN, groupFilter = ldapGroupFilter))
        case AuthenticationMethod.LdapSearch =>
          val slashIdx = ldapAuthProviderUrl.get.indexOf("/")
          val baseFromUrl = if (slashIdx > 0) {
            ldapAuthProviderUrl.get.substring(slashIdx)
          } else {
            ""
          }
          val bindName = sys.env.get("LDAP_SEARCH_BIND_NAME")
          val bindPassword = sys.env.get("LDAP_SEARCH_BIND_PASSWORD")
          val ldapDomainName = sys.env.get("LDAP_DOMAIN_NAME").orElse(sys.env.get("LDAP_SEARCH_DOMAIN_NAME"))
          val ldapBaseDN = sys.env.getOrElse("LDAP_SEARCH_BASE_DN", baseFromUrl)
          val bindFilterString = sys.env.get("LDAP_SEARCH_FILTER")
          Some(LdapAuthConfig(domainName = ldapDomainName, baseDN = Some(ldapBaseDN), base_env = env, ldapAuthPrincipal = None, bindName = bindName, bindPassword = bindPassword, bindFilterString = bindFilterString, groupDN = ldapGroupBaseDN, groupFilter = ldapGroupFilter))
        case _ =>
          None
      }
    } else {
      logger.log(Level.INFO, "no LDAP_AUTH_PROVIDER_URL")
      None
    }
  }

  private def ldapEnv(dn: String, secret: String) = {
    var env = conf.base_env
    env += javax.naming.Context.SECURITY_PRINCIPAL -> dn
    env += javax.naming.Context.SECURITY_CREDENTIALS -> secret
    val hashTable = new util.Hashtable[String, String]()
    hashTable.putAll(env.asJava)
    hashTable
  }

  private def searchStep(uName: String): Option[String] = {
    val baseDN: String = conf.baseDN.getOrElse("")

    def searchOne(filter: String, arg: String): Option[String] = {
      try {
        val controls = new SearchControls()
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        val env = ldapEnv(conf.bindName.get, conf.bindPassword.get)
        val args: Array[AnyRef] = Array(arg)
        val ctx = new InitialDirContext(env)
        try {
          val r = ctx.search(baseDN, filter, args, controls)
          if (r.hasMore) {
            val searchResult = r.next
            val name = searchResult.getNameInNamespace
            logger.info(s"Ldap searching for arg=${arg} in baseDN=${baseDN} with filter=${filter} got name=${name}")
            Some(name)
          } else {
            None
          }
        } finally {
          ctx.close()
        }
      } catch {
        case e: Exception =>
          logger.log(Level.WARNING, s"Ldap searching as user=${conf.bindName.get} rejected.", e)
          None
      }
    }

    val userPrincipalName = getPrincipalName(conf, uName)
    val samAccountName = userPrincipalName.substring(0, userPrincipalName.indexOf('@'))
    if (conf.bindFilterString.nonEmpty) {
      val filter: String = conf.bindFilterString.get
      searchOne(filter, samAccountName)
    } else {
      val filter1: String = "(& (userPrincipalName={0})(objectCategory=user))"
      val filter2: String = "(& (sAMAccountName={0})(objectCategory=user))"
      searchOne(filter1, userPrincipalName) match {
        case Some(s) => Some(s)
        case None => searchOne(filter2, samAccountName)
      }
    }
  }


  def groupsForUser(uName: String, secret: String) : Option[Set[String]] = {

    val dn = if (conf.bindName.nonEmpty) {
      // We must bind using bindName/pass to search for the user, then use the DN we find in the actual login.
      searchStep(uName)
    } else {
      // Direct bind using provided input from user:
      conf.ldapAuthPrincipal match {
        case Some(s) => Some(s.replace("HUMIOUSERNAME", uName))
        case _ => Some(uName)
      }
    }

    if (dn.isEmpty) {
      None
    } else {

      var groups = Set[String]()

      try {
        val env = ldapEnv(dn.get, secret)
        val ctx = new InitialDirContext(env)
        try {

          val groupFilter = conf.groupFilter.getOrElse("(& (objectClass=group) (member:1.2.840.113556.1.4.1941:={0}))")
          val groupBaseDN = conf.groupDN.getOrElse(dn.get)
          val searchGroupSubtree = true

          import javax.naming.directory.SearchControls
          val sc = new SearchControls
          if (searchGroupSubtree)
            sc.setSearchScope(SearchControls.SUBTREE_SCOPE)
          val answer = ctx.search(groupBaseDN, groupFilter, Seq(dn.get).toArray[AnyRef], sc)


          while (answer.hasMore) {
            val sr = answer.next
            val name = sr.getNameInNamespace
            logger.log(Level.INFO, "*** Inspecting group \"" + name + "\" for user " + uName)
            groups = groups + name
          }


        } finally {
          ctx.close()
        }
        logger.info(s"Ldap login as user=${uName} dn=${dn} succeeded.")
        Some(groups)

      } catch {
        case e: javax.naming.AuthenticationException =>
          logger.log(Level.INFO, s"Ldap login as user=${uName} dn=${dn} rejected.", e)
          None
        case e: Throwable =>
          logger.log(Level.WARNING, "Ldap authentication failed", e)
          None
      }
    }
  }

  def login(uName: String, pass: String): Option[String] = {
    if (check(uName, pass)) {

      println("*** LOGIN SUCCEEDED *** ")

      groupsForUser(uName, pass) match {
        case None => println("*** NO GROUPS FOUND ***")
        case Some(set) =>
          println("*** GROUPS ***")
          for (g <- set) {
            println( "\"" + g + "\"")
          }
      }

      Some("success!")

    } else {
      None
    }
  }

  private def check(uName: String, secret: String): Boolean = {
    logger.info(s"Ldap login for user=${uName} starting...")

    val (dn, searchAfterBind) = if (conf.bindName.nonEmpty) {
      // We must bind using bindName/pass to search for the user, then use the DN we find in the actual login.
      (searchStep(uName), true)
    } else {
      // Direct bind using provided input from user:
      conf.ldapAuthPrincipal match {
        case Some(s) => (Some(s.replace("HUMIOUSERNAME", uName)), false)
        case _ => (Some(uName), false)
      }
    }
    if (dn.nonEmpty) {
      try {
        val env = ldapEnv(dn.get, secret)
        val ctx = new InitialDirContext(env)
        try {
          if (searchAfterBind) {
            // Try a search - it throws if we are not properly logged in.
            ctx.search(dn.get, "(& (dn={0})(objectCategory=user))", Seq(dn.get).toArray[AnyRef], new SearchControls())
          }
        } finally {
          ctx.close()
        }
        logger.info(s"Ldap login as user=${uName} dn=${dn} succeeded.")
        true
      } catch {
        case e: javax.naming.AuthenticationException =>
          logger.log(Level.INFO, s"Ldap login as user=${uName} dn=${dn} rejected.", e)
          false
        case e: Throwable =>
          logger.log(Level.WARNING, "Ldap authentication failed", e)
          false
      }
    } else {
      logger.log(Level.INFO, s"Ldap login as user=${uName} dn=${dn} not tried as DN was not found.")
      false
    }
  }

  def getPrincipalName(conf: LdapAuthConfig, username: String): String = {
    val domainName: String = conf.domainName.getOrElse("")
    val slash = username.indexOf('\\')
    if (slash >= 0) {
      username.substring(slash + 1) + '@' + domainName
    } else if (username.contains("@")) {
      username
    } else {
      username + '@' + domainName
    }
  }

}

