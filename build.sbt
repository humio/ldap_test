import Dependencies._

enablePlugins(JavaServerAppPackaging)
enablePlugins(GraalVMNativeImagePlugin)

libraryDependencies ++= Seq()
javaHome := sys.env.get("JAVA_HOME") map file

lazy val root = (project in file(".")).
  settings(
    inThisBuild(List(
      organization := "com.humio",
      scalaVersion := "2.12.9",
//      crossScalaVersions := Seq("2.12.7", "2.12.8", "2.13.0-RC1"),
      version      := "0.4.0-SNAPSHOT"
    ))
    , name := "ldap-test"
//    , libraryDependencies += scalaTest % Test
    // Backports of scala.util classes from 2.13.x for Scala 2.12
    , libraryDependencies += "com.github.bigwheel" %% "util-backports" % "2.0"
    , libraryDependencies += logging
    , libraryDependencies += logback

  )

logBuffered in Test := false
logBuffered := false
mainClass in Compile := Some("com.humio.ldap_test.Main")
scalacOptions ++= Seq("-deprecation", "-feature", "-language:existentials")
scalacOptions += "-target:jvm-1.8"
javacOptions ++= Seq("-source", "1.9", "-target", "1.9")
fork := true
