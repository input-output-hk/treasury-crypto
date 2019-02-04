import treasury.crypto.core

val unitVector = for(i <- 0 until 10) yield if(i == 3) core.One else core.Zero