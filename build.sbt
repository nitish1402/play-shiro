name := """play-shiro (scala)"""

version := "1.0-SNAPSHOT"

lazy val root = (project in file(".")).enablePlugins(PlayScala)

scalaVersion := "2.11.6"

val ShiroGroup = "org.apache.shiro"
val ShiroVersion = "1.2.4"

libraryDependencies ++= Seq(
  filters,
  cache,
  ShiroGroup % "shiro-core" % ShiroVersion,
  ShiroGroup % "shiro-ehcache" % ShiroVersion,
  "org.scalatest" %% "scalatest" % "2.2.1" % Test,
  "org.scalatestplus" %% "play" % "1.4.0-M3" % Test
)

javaOptions in Test ++= Seq(
"-Xrunjdwp:transport=dt_socket,server=y,suspend=n,address=9998",
"-Xms512M",
"-Xmx1536M",
"-Xss1M",
"-XX:MaxPermSize=384M"
)

scalacOptions ++= Seq(
  "-feature",
  "-deprecation",
  "-explaintypes",
  "-language:postfixOps"
)

resolvers += "scalaz-bintray" at "http://dl.bintray.com/scalaz/releases"

// Play provides two styles of routers, one expects its actions to be injected, the
// other, legacy style, accesses its actions statically.
routesGenerator := InjectedRoutesGenerator