This software is a functional copy of the sha256sum and sha512sum tools implemented in the Rust programming language as an exercise. 

Usage:

```
rs256sum-gen 
Generate reference data

USAGE:
    rs256sum gen [FLAGS] [OPTIONS]

FLAGS:
        --from-stdin    Read names of files to hash from stdin
    -h, --help          Prints help information
        --sha512        Use SHA512
        --use-bsd       Use BSD format
    -V, --version       Prints version information

OPTIONS:
    -f, --files <files>...    Names of files to hash



rs256sum-verify 
Verify reference data

USAGE:
    rs256sum verify [FLAGS] [OPTIONS]

FLAGS:
        --from-stdin    Read reference data from stdin
    -h, --help          Prints help information
        --sha512        Use SHA512
        --use-bsd       Use BSD format
    -V, --version       Prints version information

OPTIONS:
    -i, --input <inputfile>    A file containing reference hashes
```

