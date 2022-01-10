package io.iohk.core.utils

trait HasSize {
  def size: Int
}

object SizeUtils {

  def getSize[T <: HasSize](vector: Seq[T]): Int = {
    val maxSize = if(vector.nonEmpty){ vector.maxBy(_.size).size } else { 0 }
    val totalSize = vector.foldLeft(0){(totalSize, currentElement) => totalSize + currentElement.size}

    println(maxSize + " B;\t" + totalSize + " B")

    totalSize
  }
}
