\name{setVectorSeed}
\alias{setVectorSeed}
\title{
  Initialization of Mersenne-Twister RNG with a numeric vector
  of an arbitrary nonzero length
}
\description{
  Initializes Mersenne-Twister random number generator, which is
  the default RNG in R, with a numeric vector
  of arbitrary nonzero length, whose components are
  interpreted as 32-bit integers. In order to guarantee that different input
  vectors yield unrelated streams of random numbers, Fortuna random number
  generator using AES (Advanced Encryption Standard) encryption
  algorithm is used for the transformation of \code{vseed} to the
  initial state of Mersenne-Twister. See \link{generateInitialization}
  for more detail of the algorithm.
}
\usage{
  setVectorSeed(vseed)
}
\arguments{
  \item{vseed}{ Numeric vector of arbitrary nonzero length with
                integer values from \code{[0, 2^32-1]}.}
}
\details{
  The function calls \code{RNGkind("Mersenne-Twister")} and then replaces
  its state with \code{generateInitialization(vseed)} as an initial state.
  See \code{\link{generateInitialization}} for the description of the algorithm
  computing the initialization of length 624 from \code{vseed}.
}
\value{
  \code{NULL} invisibly.
}
\seealso{
  \code{\link{generateInitialization}}.
}
\examples{
  setVectorSeed(1)
  x1 <- runif(5)
  setVectorSeed(c(1, 0))
  x2 <- runif(5)
  stopifnot(abs(x1 - c(0.30327915, 0.93045726, 0.20716215, 0.04424525, 0.07478261)) < 1e-8)
  stopifnot(abs(x2 - c(0.02231465, 0.80036017, 0.27630612, 0.69594674, 0.02688734)) < 1e-8)
}

