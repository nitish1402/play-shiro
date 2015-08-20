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
class Application @Inject() (sm: SecurityManager) extends Controller with Secure {

  override implicit def securityManager: SecurityManager = sm

  def index = Action(Ok("Home Page"))

  def basic = BasicAuth { implicit request =>
    Ok(s"Authenticated user: $user")
  }

  def logout = Logout

  def anonymous = Anonymous { implicit request =>
    Ok(s"Anonymous user: $user")
  }

  def authenticated = Authenticated { implicit request =>
    Ok(s"Authenticated user: $user")
  }

  def remembered = Remembered { implicit request =>
    Ok(s"Remembered user: $user")
  }

  def user(implicit request: SubjectRequest[_]) = request.subject.principalString.getOrElse("Unknown")

}




