import sbt._

object Dependencies {
  lazy val scalaTest = "org.scalatest" %% "scalatest" % "3.2.0-SNAP10"
  lazy val logging = "com.typesafe.scala-logging" %% "scala-logging" % "3.9.2"
  lazy val logback = "ch.qos.logback" % "logback-classic" % "1.2.3"
}
