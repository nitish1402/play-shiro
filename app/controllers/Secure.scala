package controllers

import org.apache.shiro.mgt._

/**
 * Created by jaij on 8/17/15.
 */
trait Secure {
  import shiro.Shiro._

  implicit def securityManager: SecurityManager

  val Anonymous = AnonymousAction()
  val Authenticated = Anonymous andThen AuthenticationFilter()
  val Remembered = Anonymous andThen RememberedFilter()
  val User = Anonymous andThen UserFilter()
  val BasicAuth = Anonymous andThen BasicAuthFilter()
  val FormAuth = Anonymous andThen FormAuthFilter()
  val Logout = LogoutAction()
  def Authorized(tokens: AuthorizationToken*) = AuthorizationFilter(tokens)
}
