\name{rngSetSeed-package}
\alias{rngSetSeed-package}
\alias{rngSetSeed}
\concept{set.seed}
\docType{package}

\title{Seeding the Default RNG with a Numeric Vector}

\description{
  The function \code{setVectorSeed(vseed)} is provided, which allows to
  initialize the R base Mersenne-Twister random number generator using
  a numeric vector \code{vseed} of an arbitrary nonzero length. The
  transformation of \code{vseed} into the initial state of Mersenne-Twister
  is computed using AES (Advanced Encryption Standard). The precise
  algorithm is described in \code{\link{generateInitialization}}.

  The directory "rngSetSeed/tests" contains tests, which
  \describe{
  \item{(1)}{ compare the generated random numbers to stored precomuted ones,}
  \item{(2)}{ compare the initial states obtained using AES in C-level functions
     with initial states obtained using a (slow) implementation of AES
     in R-level functions included for test purposes.}
  }
}

\seealso{
  \link{setVectorSeed},
  \link{generateInitialization}.
}

