package shiro

import org.scalatest._
import org.scalatestplus.play._

import play.api.mvc._
import play.api.test._
import play.api.test.Helpers._

/**
 * Created by jaij on 7/17/15.
 */
class SecurityActionsSpec extends PlaySpec {

  class TestSecurityActions extends Controller with SecurityActions

  "AnonymousAction" should {
    "provide a subject" in {
      val controller = new TestSecurityActions()
      FakeRequest()
      controller.AnonymousAction().apply { request =>
        Results.Ok
      }
    }
  }

}
