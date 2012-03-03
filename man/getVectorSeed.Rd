\name{getVectorSeed}
\alias{getVectorSeed}
\title{
  Generates an integer vector of length 624.
}
\description{
  Generates an integer vector of length 624 suitable as an initial state of Mersenne-Twister
  random number generator.
}
\usage{
  getVectorSeed(vseed)
}
\arguments{
  \item{vseed}{ Numeric vector of an arbitrary nonzero length with integer
   values from \code{[0, 2^32-1]}.}
}
\details{
  The algorithm consists of two phases.

  Phase 1. The vector \code{vseed} is first replaced by \code{c(vseed, length(vseed))}.
  If the length of the resulting vector is not divisible by 8, the vector
  is padded by zeros to the nearest larger length divisible by 8.
  The resulting vector is splitted into blocks of length 8 and these
  blocks are used as 256-bit keys in Davies-Meyer scheme, see
  \url{http://en.wikipedia.org/wiki/One-way_compression_function}
  using AES (Advanced Encryption Standard) as the block cipher.

  Phase 2. The hash value of length 16 bytes obtained in phase 1 is used as a
  128-bit key in AES to encrypt a counter sequence \code{0, ..., 623}. The first
  4 bytes of each of the obtained 624 encrypted values are combined to
  one 32-bit component of the output state in an endianness independent way. This
  algorithm belongs among Fortuna random number generators as described at
  \url{http://en.wikipedia.org/wiki/Fortuna_(PRNG)}.
}
\value{
  Integer vector of length 624 suitable as the initial state of
  Mersenne-Twister to be copied into \code{.Random.seed[3:626]}.
}
\references{
  \url{http://en.wikipedia.org/wiki/Advanced_Encryption_Standard},
  \url{http://en.wikipedia.org/wiki/Fortuna_(PRNG)}.
}
\seealso{
  \code{\link{setVectorSeed}}
}
\examples{
  s <- getVectorSeed(1)
  length(s)
}

