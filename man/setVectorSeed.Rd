\name{setVectorSeed}
\alias{setVectorSeed}
\title{
  Initializes Mersenne-Twister random number generator with a vector
  of arbitrary nonzero length.
}
\description{
  Initializes Mersenne-Twister random number generator with a numeric vector
  of arbitrary nonzero length, whose components are interpreted as 32-bit
  integers. In order to guarantee that different input vectors yield
  unrelated streams of random numbers, a hash function based on AES
  (Advanced Encryption Standard) is used for the transformation of \code{vseed}
  to the initial state of Mersenne-Twister.
}
\usage{
  setVectorSeed(vseed)
}
\arguments{
  \item{vseed}{Numeric vector of arbitrary nonzero length with integer values from \code{[0, 2^32-1]}.}
}
\details{
  The function calls \code{RNGkind("Mersenne-Twister")} and then replaces
  its state with \code{getVectorSeed(vseed)} as an initial state.
  See \code{\link{getVectorSeed}} for the description of the algorithm
  computing the initialization of length \code{624} from \code{vseed} using
  AES (Advanced Encryption Standard) as a hash function.
}
\value{
  \code{NULL} invisibly.
}
\seealso{
  \code{\link{getVectorSeed}}.
}
\examples{
  setVectorSeed(1)
  runif(5)
  setVectorSeed(2)
  runif(5)
  setVectorSeed(1)
  runif(5)
}

