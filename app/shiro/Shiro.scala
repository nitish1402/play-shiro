package shiro

import java.io.Serializable

import org.apache.shiro.authc._
import org.apache.shiro.codec._
import org.apache.shiro.mgt._
import org.apache.shiro.session.{Session => ShiroSession}
import org.apache.shiro.subject.Subject._
import org.apache.shiro.subject._
import play.api.Play.current
import play.api._
import play.api.data.Forms._
import play.api.data._
import play.api.http.HeaderNames._
import play.api.mvc.Results._
import play.api.mvc._

import scala.concurrent._
import scala.util._
import scala.collection.JavaConversions._

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
    def isAnonymous = !isUser
    def session: Option[ShiroSession] = Option(subject.getSession(false))
    def sessionId: Option[Serializable] = session.map(_.getId)
    def sessionIdString: Option[String] = sessionId.map(_.toString)
  }

  type SubjectFactory = (SecurityManager, RequestHeader, Boolean, Boolean, PrincipalCollection) => Subject
  type SRequest = SubjectRequest[_]

  val SessionId = Play.configuration.getString("shiro.sessionid").getOrElse("sessionid")
  val HostFromRequest: RequestHeader => Option[String] = req => Option(req.remoteAddress)
  val SessionIdFromRequest: RequestHeader => Option[String] = _.session.get(SessionId)

  val AccessDeniedUnauthorized = Some(Unauthorized)
  val AccessDeniedForbidden = Some(Forbidden)

  val RedirectHome = Redirect("/")

  lazy val NoPrincipals = new SimplePrincipalCollection()

  val SubjectFromRequest: SubjectFactory = { (sm, req, sessionCreation, authenticated, principals) =>
    val builder = new Builder(sm)
    SessionIdFromRequest(req).foreach(builder.sessionId)
    HostFromRequest(req).foreach(builder.host)
    builder.sessionCreationEnabled(sessionCreation)
    builder.authenticated(authenticated)
    builder.principals(principals)
    builder.buildSubject()
  }

  //----------------------------------------------------------------------------------------------------
  // ActionBuilders that put a Shiro Subject in the Request
  //----------------------------------------------------------------------------------------------------

  class SubjectRequest[A](val subject: Subject, request: Request[A]) extends WrappedRequest[A](request) {
    def isAuthenticated: Boolean = subject.isAuthenticated
    def isRemembered: Boolean = subject.isRemembered
    def isUser: Boolean = subject.isUser
    def isAnonymous: Boolean = subject.isAnonymous
  }

  class SubjectActionBuilder(subject: SubjectFactory,
    sessionCreation: Boolean,
    authenticated: Boolean,
    principals: PrincipalCollection)
    (implicit sm: SecurityManager)
    extends ActionBuilder[SubjectRequest]
    with ActionFunction[Request, SubjectRequest] {

    override def invokeBlock[A](request: Request[A], block: (SubjectRequest[A]) => Future[Result]): Future[Result] = {
      val srequest = new SubjectRequest(subject(sm, request, sessionCreation, authenticated, principals), request)
      block(srequest).map(result => writeSessionId(srequest, result))(executionContext)
    }

    protected def writeSessionId(request: SRequest, result: Result) =
      request.subject.sessionIdString.fold(result)(id => result.withSession(request.session + (SessionId -> id)))
  }

  def AnonymousAction(subject: SubjectFactory = SubjectFromRequest,
    sessionCreation: Boolean = true,
    authenticated: Boolean = false,
    principals: PrincipalCollection = NoPrincipals)
    (implicit sm: SecurityManager): ActionBuilder[SubjectRequest] =
    new SubjectActionBuilder(subject, sessionCreation, authenticated, principals)

  //----------------------------------------------------------------------------------------------------
  // ActionFilters that restrict access to logged in users
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
          Logger(this.getClass).debug(s"Authenticated User: $token")
          authSuccess(token, request)
        } recover {
          case e: AuthenticationException => authFailure(token, request, e)
        } get
      }
    }

  def BasicAuthFilter(
    authRealm: Option[String] = None,
    authSuccess: (AuthenticationToken, SRequest) => Option[Result] = (_,_) => None,
    accessDenied: SRequest => Option[Result] = _ => AccessDeniedUnauthorized
  ) = AuthenticatingFilter(BasicAuth.authToken, authSuccess, BasicAuth.authFailure(authRealm) _, accessDenied)

  object BasicAuth {
    def authFailure(authRealm: Option[String])(token: AuthenticationToken, request: SRequest, ex: AuthenticationException): Option[Result] = {
      val ChallengeHeader = WWW_AUTHENTICATE -> authRealm.fold("Basic")(r => s"""Basic realm="$r"""".trim)
      Some(Unauthorized.withHeaders(ChallengeHeader))
    }

    def authToken(request: SRequest): Option[AuthenticationToken] = {
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
  }

  def FormAuthFilter(
    authToken: SRequest => Option[AuthenticationToken] = FormAuth.AuthToken,
    authSuccess: (AuthenticationToken, SRequest) => Option[Result] = (_,_) => None,
    authFailure: (AuthenticationToken, SRequest, AuthenticationException) => Option[Result] = (_,_,_) => AccessDeniedUnauthorized,
    accessDenied: SRequest => Option[Result] = _ => AccessDeniedUnauthorized
  ) = AuthenticatingFilter(authToken, authSuccess, authFailure, accessDenied)

  object FormAuth {
    val SimpleUserForm = Form(
      mapping(
        "username" -> nonEmptyText,
        "password" -> nonEmptyText,
        "rememberme" -> boolean
      )((username, password, rememberme) => new UsernamePasswordToken(username, password, rememberme))
        (token => Some(token.getUsername, token.getPassword.mkString, token.isRememberMe))
    )

    val AuthToken: SRequest => Option[AuthenticationToken] = { implicit request =>
      val maybeForm = SimpleUserForm.bindFromRequest.value
      maybeForm.foreach(_.setHost(request.remoteAddress))
      maybeForm
    }
  }

  //----------------------------------------------------------------------------------------------------
  // ActionFilters that restrict access to users by role/permission
  //----------------------------------------------------------------------------------------------------
  sealed trait AuthorizationToken extends Any {
    def name: String
    def isRole: Boolean = this.isInstanceOf[Role]
    def isPermission: Boolean = this.isInstanceOf[Permission]
  }
  case class Role(name: String) extends AnyVal with AuthorizationToken
  case class Permission(name: String) extends AnyVal with AuthorizationToken

  def AuthorizationFilter(
    tokens: Seq[AuthorizationToken] = Seq.empty,
    accessDenied: SRequest => Option[Result] = _ => AccessDeniedForbidden) = new AccessControlFilter({ req =>
      val subj = req.subject
      val (roles, permissions) = tokens.partition(_.isRole)
      subj.hasAllRoles(roles.map(_.name)) && subj.isPermittedAll(permissions.map(_.name): _*)
    }, accessDenied)

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