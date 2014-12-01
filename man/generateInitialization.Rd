\name{generateInitialization}
\alias{generateInitialization}
\title{
  Generates a random integer vector of a specified length using AES.
}
\description{
  In a typical application of the package, this function is not called
  directly by the user and the function is called from \code{setVectorSeed()}.
  The function is made available in order to simplify testing correctness
  of the package and the documentation of this function explains the exact
  algorithm used by \code{setVectorSeed()}.
}
\usage{
  generateInitialization(vseed, m)
}
\arguments{
  \item{vseed}{ Numeric vector of an arbitrary nonzero length, whose components
    have integer values from \code{[0, 2^32 - 1]}.}
  \item{m}{ Numeric, the length of the required output integer vector.}
}
\details{
  The function transforms an input vector \code{vseed} of an arbitrary length
  to a random integer vector of length \code{m} using Advanced Encryption
  Standard (AES) block cipher. The function \code{setVectorSeed()} calls
  \code{generateInitialization(vseed, 624)} and uses its output as an initial
  state of the R base Mersenne-Twister random number generator.

  The vector \code{vseed} is first replaced by \code{c(vseed, length(vseed))}
  in order to guarantee that if \code{vseed1} is a prefix of \code{vseed2},
  but they have a different length, then the outputs are unrelated. If the length
  of the resulting vector is not divisible by 8, the vector is padded by zeros
  to the nearest larger length divisible by 8 in order to meet the requirements
  of the AES algorithm. The resulting vector is splitted into blocks of length 8
  and these blocks are used as 256-bit keys in AES. Each of these keys is used
  to encrypt a counter sequence of length \code{ceiling(m/4)}. The encrypted
  values of these sequences are combined by XOR to a single sequence of
  \code{ceiling(m/4)} values, each of which is a sequence of 16 bytes. These
  sequences are splitted into subsequences of 4 bytes, each of which encodes
  a 32-bit integer in an endianness independent way. The first \code{m} of the
  obtained integers form the output.

  If \code{length(vseed) <= 7}, then the above algorithm is known as Fortuna random
  number generator using AES as described at
  \url{http://en.wikipedia.org/wiki/Fortuna_(PRNG)} with a key specified
  by the user.
  If \code{length(vseed) >= 8}, the algorithm uses XOR of the outputs
  of several Fortuna generators with keys formed from disjoint parts of
  the input vector and disjoint counter sequences.

  If \code{m1 < m2}, then \code{generateInitialization(vseed, m1)} is equal
  to the first \code{m1} components of \code{generateInitialization(vseed, m2)}.
}
\value{
  Vector of length \code{m} of integer type suitable for substituting into 
  the components of \code{.Random.seed}. This means that the components
  are integers from the interval \code{[-2^31 + 1, 2^31 - 1]} or \code{NA},
  which represents \code{-2^31}. If \code{m == 624}, the output vector is
  suitable as the initial state of Mersenne-Twister to be copied into
  \code{.Random.seed[3:626]}. 
}
\references{
  \url{http://en.wikipedia.org/wiki/Advanced_Encryption_Standard},
  \url{http://en.wikipedia.org/wiki/Fortuna_(PRNG)}.
}
\seealso{
  \code{\link{setVectorSeed}}
}
\examples{
  generateInitialization(0, 3) == c(1418754292, -1328910215, -1268802982)
  generateInitialization(c(0, 1), 3) == c(1456767579, 1606355844, -1560283904)
  generateInitialization(c(0, 1, 2), 3) == c(-1265102184, -974528510, 163341403)
  generateInitialization(c(0, 1, 2), 3) == generateInitialization(c(0, 1, 2), 33)[1:3]
}

