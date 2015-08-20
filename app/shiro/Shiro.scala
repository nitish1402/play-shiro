package shiro

import java.io.Serializable
import javax.inject._

import org.apache.shiro.authc._
import org.apache.shiro.codec._
import org.apache.shiro.config._
import org.apache.shiro.mgt._
import org.apache.shiro.session.{Session => ShiroSession}
import org.apache.shiro.subject.Subject._
import org.apache.shiro.subject._
import org.apache.shiro.util._
import play.api._
import play.api.i18n.Messages._
import play.api.inject._
import play.api.mvc.Results._
import play.api.mvc._
import play.api.http.HeaderNames._
import Play.current
import scala.concurrent._
import scala.util._

/**
 * Shiro components for compile time injection
 */
trait ShiroComponents {

  def environment: Environment
  def configuration: Configuration
  def applicationLifecycle: ApplicationLifecycle

  lazy val iniSecurityManager: SecurityManager = new IniSecurityManagerProvider(configuration, environment, applicationLifecycle).get
}

@Singleton
class ShiroModule extends Module {
  override def bindings(environment: Environment, configuration: Configuration): Seq[Binding[_]] = Seq(
    bind(classOf[SecurityManager]).toProvider(classOf[IniSecurityManagerProvider])
  )
}

@Singleton
class IniSecurityManagerProvider @Inject() (config: Configuration, env: Environment, lifecycle: ApplicationLifecycle) extends Provider[SecurityManager] {
  override def get(): SecurityManager = {
    val securityManager = new IniSecurityManagerFactory({
      config.getString("shiro.inifile").getOrElse("classpath:shiro.ini")
    }).getInstance()

    // Implement shutdown hook to close resources on application shutdown
    securityManager match {
      case x: Destroyable => lifecycle.addStopHook(() => Future.successful(x.destroy()))
      case x => x
    }

    securityManager
  }
}

object Shiro {

  /**
   * Decorates Shiro Subject with helper methods
   *
   * @param subject
   */
  implicit class SubjectWrapper(val subject: Subject) extends AnyVal {
    def principal: Option[AnyRef] = Option(subject.getPrincipal)
    def principalString: Option[String] = principal.map(_.toString)
    def isUser = subject.isAuthenticated || subject.isRemembered
    def session: Option[ShiroSession] = Option(subject.getSession(false))
    def sessionId: Option[Serializable] = session.map(_.getId)
    def sessionIdString: Option[String] = sessionId.map(_.toString)
  }

  type SubjectFactory = (SecurityManager, RequestHeader) => Subject
  type SRequest = SubjectRequest[_]

  val SessionId = Play.configuration.getString("shiro.sessionid").getOrElse("sessionid")
  val HostFromRequest: RequestHeader => Option[String] = req => Option(req.remoteAddress)
  val SessionIdFromRequest: RequestHeader => Option[String] = _.session.get(SessionId)
  val AccessDeniedUnauthorized = Some(Unauthorized)
  val AccessDeniedForbidden = Some(Forbidden)
  val RedirectHome = Redirect("/")

  val SubjectFromRequest: SubjectFactory = { (sm, req) =>
    val builder = new Builder(sm)
    SessionIdFromRequest(req).foreach(builder.sessionId)
    HostFromRequest(req).foreach(builder.host)
    builder.sessionCreationEnabled(false)
    builder.buildSubject()
  }

  //----------------------------------------------------------------------------------------------------
  // ActionBuilders that put a Shiro Subject in the Request
  //----------------------------------------------------------------------------------------------------

  class SubjectRequest[A](val subject: Subject, request: Request[A]) extends WrappedRequest[A](request) {
    def isAuthenticated: Boolean = subject.isAuthenticated
    def isRemembered: Boolean = subject.isRemembered
    def isUser: Boolean = subject.isUser
  }

  class SubjectActionBuilder(subject: SubjectFactory)(implicit sm: SecurityManager)
    extends ActionBuilder[SubjectRequest]
    with ActionFunction[Request, SubjectRequest] {

    override def invokeBlock[A](request: Request[A], block: (SubjectRequest[A]) => Future[Result]): Future[Result] = {
      val s = subject(sm, request)
      block(new SubjectRequest(s, request)).map { r =>
        s.sessionIdString.fold(r)(id => r.withSession(request.session + (SessionId -> id)))
      }(executionContext)
    }
  }

  def AnonymousAction(subject: SubjectFactory = SubjectFromRequest)(implicit sm: SecurityManager): ActionBuilder[SubjectRequest] =
    new SubjectActionBuilder(subject)

  //----------------------------------------------------------------------------------------------------
  // ActionFilters that restrict access to Controllers
  //----------------------------------------------------------------------------------------------------
  class AccessControlFilter(accessAllowed: SRequest => Boolean, accessDenied: SRequest => Option[Result])
    extends ActionFilter[SubjectRequest] {

    override protected def filter[A](request: SubjectRequest[A]): Future[Option[Result]] = Future.successful {
      if (accessAllowed(request)) None
      else accessDenied(request)
    }
  }

  def UserFilter(accessDenied: SRequest => Option[Result] = _ => AccessDeniedUnauthorized) =
    new AccessControlFilter(_.isUser, accessDenied)

  def RememberedFilter(accessDenied: SRequest => Option[Result] = _ => AccessDeniedUnauthorized) =
    new AccessControlFilter(_.isRemembered, accessDenied)

  def AuthenticationFilter(accessDenied: SRequest => Option[Result] = _ => AccessDeniedUnauthorized) =
    new AccessControlFilter(_.isAuthenticated, accessDenied)

  //----------------------------------------------------------------------------------------------------
  // ActionFilters that authenticate a user/subject
  //----------------------------------------------------------------------------------------------------

  /**
   * Checks if the user/subject is authenticated, if not it tries to authenticate using info in the request
   *
   * @param authToken
   * @param authSuccess
   * @param authFailure
   * @param accessDenied
   * @return
   */
  def AuthenticatingFilter(
    authToken: SRequest => Option[AuthenticationToken],
    authSuccess: (AuthenticationToken, SRequest) => Option[Result] = (_,_) => None,
    authFailure: (AuthenticationToken, SRequest, AuthenticationException) => Option[Result] = (_,_,_) => AccessDeniedUnauthorized,
    accessDenied: SRequest => Option[Result] = _ => AccessDeniedUnauthorized
  ) = AuthenticationFilter { request =>
      // if there authentication info in the request use it to login
      authToken(request).fold(accessDenied(request)) { token =>
        Try {
          request.subject.login(token)
          authSuccess(token, request)
        } recover {
          case e: AuthenticationException => authFailure(token, request, e)
        } get
      }
    }

  def BasicAuthFilter(
    authRealm: Option[String] = None,
    authSuccess: (AuthenticationToken, SRequest) => Option[Result] = (_,_) => None,
    accessDenied: SRequest => Option[Result] = _ => AccessDeniedUnauthorized) = {

    def authFailure(token: AuthenticationToken, request: SRequest, ex: AuthenticationException) = {
      val ChallengeHeader = WWW_AUTHENTICATE -> authRealm.fold("Basic")(r => s"""Basic realm="$r"""".trim)
      Some(Unauthorized(ex.getMessage).withHeaders(ChallengeHeader))
    }

    def authToken(request: SRequest) = {
      def credentialsFromHeader: Option[String] = {
        request.headers.get(AUTHORIZATION).flatMap { header =>
          header.split("Basic\\s", 2) match {
            case Array(_, credentials) => Some(credentials)
            case _ => None
          }
        }
      }

      def decodeCredentials(credentials: String): Option[(String, String)] = {
        Base64.decodeToString(credentials).split(":", 2) match {
          case Array(username, password) => Some(username -> password)
          case _ => None
        }
      }

      for {
        credentials <- credentialsFromHeader
        (username, password) <- decodeCredentials(credentials)
      } yield new UsernamePasswordToken(username, password)

    }

    AuthenticatingFilter(authToken, authSuccess, authFailure, accessDenied)
  }

  //----------------------------------------------------------------------------------------------------
  // Other Filters
  //----------------------------------------------------------------------------------------------------
  def LogoutAction(subject: SubjectFactory = SubjectFromRequest, result: Result = RedirectHome)(implicit sm: SecurityManager) =
    AnonymousAction(subject).apply { request =>
      try {
        request.subject.logout()
      } catch {
        case e: Exception => Logger(this.getClass).info("Session error while logging out, safe to ignore", e)
      }
      result.withNewSession
    }
}