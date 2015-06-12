lazy val commonSettings = Seq(
    name := "MessageMayFileSigning",
    version := "0.1.0",
    scalaVersion := "2.11.6"
  )
  
libraryDependencies += "org.bouncycastle" % "bcprov-jdk15on" % "1.52" withSources() withJavadoc()
libraryDependencies += "commons-codec" % "commons-codec" % "1.10" withSources() withJavadoc()
libraryDependencies += "org.apache.commons" % "commons-lang3" % "3.4" withSources() withJavadoc()
libraryDependencies += "commons-cli" % "commons-cli" % "1.3" withSources() withJavadoc()

