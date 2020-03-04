package io.iohk.core.utils

import org.scalameter.{Key, Measurer, Warmer, config}

object TimeUtils {

  def time[R](block: => R): R = {
    val t0 = System.nanoTime()
    val result = block
    val t1 = System.nanoTime()
    println("Elapsed time: " + (t1-t0)/1000000000 + " sec")
    result
  }

  def time[R](msg: String, block: => R): R = {
    val t0 = System.nanoTime()
    val result = block
    val t1 = System.nanoTime()
    println(msg + " " + (t1-t0)/1000000000 + " sec")
    result
  }

  def time_ms[R](msg: String, block: => R): R = {
    val t0 = System.nanoTime()
    val result = block
    val t1 = System.nanoTime()
    println(msg + " " + (t1-t0)/1000000 + " ms")
    result
  }

  def get_time_average_s[R](msg: String, block: => R, n: Int): (R, Float) = {
    val t0 = System.nanoTime()
    val result = block
    val t1 = System.nanoTime()
    val time = ((t1-t0).toFloat/1000000000)/n
    print(msg + "\t" + time + " s;\t")
    (result, time)
  }

  def accurate_time[R](msg: String, block: => R): Unit = {
    val time = config(
      Key.exec.benchRuns -> 20,
    ) withWarmer {
      new Warmer.Default
    } withMeasurer {
      new Measurer.IgnoringGC
    } measure {
      block
    }
    println(msg + " " + time.value.toInt  + " ms")
  }
}
