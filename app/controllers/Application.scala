package controllers

import java.util._
import javax.inject._

import org.apache.shiro.authc._
import org.apache.shiro.mgt._
import play.api.data.Forms._
import play.api.data._
import play.api.http.HeaderNames._
import play.api.mvc.Results._
import play.api.mvc._
import shiro.Shiro._
import org.apache.shiro.codec.Base64
import scala.util._

@Singleton
class Application @Inject() (implicit val securityManager: SecurityManager) extends Controller with Secure {

  def index = Action(Ok("Home Page"))

  def anonymous = Anonymous { implicit request =>
    Ok(s"Anonymous User: $username")
  }

  def user = User { implicit request =>
    Ok(s"User: $username")
  }

  def authenticated = Authenticated { implicit request =>
    Ok(s"Authenticated User: $username")
  }

  def remembered = Remembered { implicit request =>
    Ok(s"Remembered User: $username")
  }

  def basic = BasicAuth { implicit request =>
    Ok(s"Authenticated Basic Auth User: $username")
  }

  def form = FormAuth { implicit request =>
    Ok(s"Authenticated Form Auth User: $username")
  }

  def authorized(roles: Seq[String], permissions: Seq[String]) =
    (Authenticated andThen Authorized(roles.map(Role) ++ permissions.map(Permission): _*)) { implicit request =>
    Ok(s"Authorized (by Role) User: $username")
  }

  def logout = Logout

  def username(implicit request: SubjectRequest[_]) = request.subject.principalString.getOrElse("Unknown")

}




