module github.com/foxgirlsorg/tamamo/examples/hello

go 1.25

require github.com/foxgirlsorg/tamamo v0.0.0

// The example lives in Tamamo's own repository, so it builds against the
// source next to it. A module in its own repository has no replace line:
// "go get github.com/foxgirlsorg/tamamo@latest" pins a released version.
replace github.com/foxgirlsorg/tamamo => ../..
