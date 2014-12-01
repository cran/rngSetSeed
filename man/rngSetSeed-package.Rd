\name{rngSetSeed-package}
\alias{rngSetSeed}
\concept{set.seed}
\docType{package}

\title{Initialization of Mersenne-Twister random number generator using AES.}

\description{
  The package provides function \code{setVectorSeed(vseed)}, which allows to
  initialize the R base Mersenne-Twister random number generator using a numeric
  vector \code{vseed} of arbitrary nonzero length, including length 1. In order
  to guarantee that different seeding vectors yield unrelated streams of
  random numbers, the transformation of \code{vseed} into the initial state
  of Mersenne-Twister is computed by Fortuna random number generator using
  Advanced Encryption Standard (AES) as the underlying block cipher.

  Initializing using a vector seed may be used to provide reproducible and
  unrelated streams of random numbers in independent R processes, each of
  which knows its reproducible index (not a process number). For this purpose,
  use something like \code{setVectorSeed(c(base.seed, ind, i, j))}, where
  \code{base.seed} is a global seed for a group of R processes, \code{ind}
  is an index of the R process and \code{i, j} may be loop variables of nested
  \code{for} loops, for each repetition of which we want to start a new
  stream of random numbers.

  The directory "rngSetSeed/tests" contains tests, which
  \describe{
  \item{(1)}{ compare the generated random numbers to stored precomuted ones,}
  \item{(2)}{ compare the initial states obtained using AES in C-level functions
     with initial states obtained using a (slow) implementation of AES
     in R-level functions included for test purposes.}
  }
}

\seealso{
  \code{\link{setVectorSeed}},
  \code{\link{generateInitialization}}.
}

