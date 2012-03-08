\name{getVectorSeed}
\alias{getVectorSeed}
\title{
  Generates a random integer vector of a specified length using AES.
}
\description{
  Transforms an input vector of an arbitrary length to a random integer
  vector of a specified length using Advanced Encryption Standard (AES)
  block cipher. If the output length is 624, then it is suitable as an
  initial state of Mersenne-Twister random number generator.
}
\usage{
  getVectorSeed(vseed, m)
}
\arguments{
  \item{vseed}{ Numeric vector of an arbitrary nonzero length, whose components
    have integer values from \code{[0, 2^32 - 1]}.}
  \item{m}{ Numeric, the length of the required output integer vector.}
}
\details{
  The vector \code{vseed} is first replaced by \code{c(vseed, length(vseed))}
  in order to guarantee that if \code{vseed1} is the first part of \code{vseed2},
  but they have a different length, then the outputs are unrelated. If the length
  of the resulting vector is not divisible by 8, the vector
  is padded by zeros to the nearest larger length divisible by 8. The resulting
  vector is splitted into \code{k} blocks of length 8 and these blocks are used
  as 256-bit keys in AES to encrypt \code{k} different counter sequences of
  length \code{mm == ceiling(m/4)}. The encrypted values from all \code{k} rounds
  are combined by XOR to a single sequence of \code{mm} values, each of which is
  a sequence of 16 bytes. These sequences are splitted into subsequences of
  4 bytes. Each of these \code{4*mm} subsequences is combined to one 32-bit integer
  in an endianness independent way. The first \code{m} of the obtained integers
  form the output.

  The first round, which is the only round, if \code{length(vseed) <= 7},
  is Fortuna random number generator using AES as described at
  \url{http://en.wikipedia.org/wiki/Fortuna_(PRNG)} with a key specified
  by the user.
  If \code{length(vseed) >= 8}, the algorithm uses XOR of the outputs
  of several Fortuna generators with keys formed from disjoint parts of
  the input vector and disjoint counter sequences.

  If \code{m1 < m2}, then the first \code{m1} components of \code{getVectorSeed(vseed, m2)}
  and \code{getVectorSeed(vseed, m1)} are equal.
}
\value{
  Vector of length \code{m} of integer type. Its components are from
  \code{[-2^31 + 1, 2^31 - 1]} or \code{NA}, which represents \code{-2^31}.
  These values are interpreted as unsigned integers
  in \code{[0, 2^32 - 1]} modulo \code{2^32}. If \code{m == 624}, the
  output vector is suitable as the initial state of Mersenne-Twister
  to be copied into \code{.Random.seed[3:626]}. 
}
\references{
  \url{http://en.wikipedia.org/wiki/Advanced_Encryption_Standard},
  \url{http://en.wikipedia.org/wiki/Fortuna_(PRNG)}.
}
\seealso{
  \code{\link{setVectorSeed}}
}
\examples{
  getVectorSeed(0, 3) == c(1418754292, -1328910215, -1268802982)
  getVectorSeed(c(0, 1), 3) == c(1456767579, 1606355844, -1560283904)
  getVectorSeed(c(0, 1, 2), 3) == c(-1265102184, -974528510, 163341403)
  getVectorSeed(c(0, 1, 2), 3) == getVectorSeed(c(0, 1, 2), 33)[1:3]
}

