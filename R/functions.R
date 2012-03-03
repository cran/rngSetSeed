setVectorSeed <- function(vseed)
{
    RNGkind("Mersenne-Twister")
    stopifnot(.Random.seed[1] %% 100 == 3)
    stopifnot(.Random.seed[2] == 624)
    newState <- getVectorSeed(vseed)
    stopifnot(length(newState) == 624)
    .Random.seed[3:626] <<- newState
    invisible(NULL)
}

getVectorSeed <- function(vseed)
{
    if (any(vseed != floor(vseed))) stop("Vector seed should have integer components")
    if (any(vseed < 0 | vseed >= 2^32)) stop("Vector seed should have components in [0, 2^32-1]")
	vseed <- c(vseed, length(vseed))
    s <- numeric(8*ceiling(length(vseed)/8))
    s[seq.int(along.with=vseed)] <- vseed
    .C("getVectorSeed",
        length(s),
        as.double(s),
        out=integer(624),
        PACKAGE="rngSetSeed")$out
}

