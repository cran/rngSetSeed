\name{rngSetSeed-package}
\alias{rngSetSeed}
\concept{set.seed}
\docType{package}

\title{Initialization of Mersenne-Twister random number generator using AES}

\description{
The package provides function \code{setVectorSeed(vseed)}, which allows to
initialize the R base Mersenne-Twister random number generator using a vector
\code{vseed} of arbitrary nonzero length, including length one. In order
to guarantee that different seeding vectors yield unrelated streams of
random numbers, the transformation of \code{vseed} into the initial state
of Mersenne-Twister is computed using a hash function based on Advanced
Encryption Standard (AES).

Initializing using a vector seed may be used to provide reproducible
and unrelated streams of random numbers in independent R processes
using for example \code{setVectorSeed(c(base.seed, ind, i, j))}, where
\code{base.seed} is a global seed for a group of R processes, \code{ind}
is an index of an R process within this group and \code{i,j} are loop
variables of nested \code{for} loops, for each repetition of which we
want to start a new stream of random numbers.

The directory "rngSetSeed/tests" of the package contains tests, which
\describe{
\item{(1)}{ compare the generated random numbers to stored precomuted ones,}
\item{(2)}{ compare the initial states obtained using AES in C-level functions
   with initial states obtained using a (very slow) implementation of AES
   in R-level functions.}
}
}

\seealso{
  \code{\link{setVectorSeed}},
  \code{\link{getVectorSeed}}.
}

