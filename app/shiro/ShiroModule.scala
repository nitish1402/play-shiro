package shiro

import javax.inject._

import org.apache.shiro.config._
import org.apache.shiro.mgt._
import org.apache.shiro.util._
import play.api._
import play.api.inject._

import scala.concurrent._

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
    bind(classOf[SecurityManager]).toProvider(classOf[IniSecurityManagerProvider]).eagerly()
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