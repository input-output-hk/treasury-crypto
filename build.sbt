name := "treasury-crypto"

version := "0.1"

scalaVersion := "2.12.3"

libraryDependencies ++= Seq(
  "org.bouncycastle" % "bcprov-jdk15on" % "1.58",
  "org.scalatest" %% "scalatest" % "3.0.+" % "test"
)