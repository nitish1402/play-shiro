package controllers

import org.apache.shiro.mgt._
import play.api.mvc.Results._
import play.api.http.HeaderNames._

/**
 * Created by jaij on 8/17/15.
 */
trait Secure {
  import shiro.Shiro._

  implicit def securityManager: SecurityManager

  val Anonymous = AnonymousAction()
  val Authenticated = Anonymous andThen AuthenticationFilter()
  val Remembered = Anonymous andThen RememberedFilter()
  val BasicAuth = Anonymous andThen BasicAuthFilter()
  val Logout = LogoutAction()
}