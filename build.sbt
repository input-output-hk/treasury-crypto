name := "treasury-crypto"

version := "0.1"

scalaVersion := "2.12.3"

resolvers += "Sonatype OSS Snapshots" at
  "https://oss.sonatype.org/content/repositories/snapshots"

libraryDependencies ++= Seq(
  "org.bouncycastle" % "bcprov-jdk15on" % "1.58",
  "org.scalatest" %% "scalatest" % "3.0.+" % "test",
  "org.json" % "json" % "20170516",
  "com.storm-enroute" %% "scalameter" % "0.8.2" % "bench"
)

testFrameworks += new TestFramework(
  "org.scalameter.ScalaMeterFramework")

logBuffered := false
parallelExecution in Test := false

lazy val Benchmark = config("bench") extend Test

lazy val basic = (project in file(".")).configs(Benchmark).settings(inConfig(Benchmark)(Defaults.testSettings): _*)