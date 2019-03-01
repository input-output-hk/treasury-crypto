name := "treasury-crypto"

version := "0.1"

scalaVersion := "2.12.3"

resolvers += "Sonatype OSS Snapshots" at
  "https://oss.sonatype.org/content/repositories/snapshots"

libraryDependencies ++= Seq(
  "org.bouncycastle" % "bcprov-jdk15on" % "1.58",
  "org.scalatest" %% "scalatest" % "3.0.+" % "test",
  "org.json" % "json" % "20170516",
  "com.storm-enroute" %% "scalameter" % "0.8.2" % "bench",
  "com.storm-enroute" %% "scalameter-core" % "0.8.2",
  "com.google.guava" % "guava" % "20.0",
  "com.github.jnr" % "jnr-ffi" % "2.0.9"
)

////////////////////////////////////////////
// Run scalastyle as part of the tests
// TODO Uncomment the following three lines
// lazy val compileScalastyle = taskKey[Unit]("compileScalastyle")
// compileScalastyle := scalastyle.in(Compile).toTask("").value
// (compile in Compile) := ((compile in Compile) dependsOn compileScalastyle).value

testFrameworks += new TestFramework(
  "org.scalameter.ScalaMeterFramework")

logBuffered := false
parallelExecution in Test := false

lazy val Benchmark = config("bench") extend Test

lazy val basic = (project in file(".")).configs(Benchmark).settings(inConfig(Benchmark)(Defaults.testSettings): _*)
