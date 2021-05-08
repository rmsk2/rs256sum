This software is a functional copy of the sha256sum and sha512sum tools implemented in the Rust programming language as an exercise. 

Usage:

```
rs256sum-gen 
Generate reference data

USAGE:
    rs256sum gen [FLAGS] --files <files>...

FLAGS:
    -h, --help       Prints help information
        --sha512     Use SHA512
        --use-bsd    Use BSD format
    -V, --version    Prints version information

OPTIONS:
    -f, --files <files>...    All files to hash



rs256sum-verify 
Verify reference data

USAGE:
    rs256sum verify [FLAGS] --input <inputfile>

FLAGS:
    -h, --help       Prints help information
        --sha512     Use SHA512
        --use-bsd    Use BSD format
    -V, --version    Prints version information

OPTIONS:
    -i, --input <inputfile>    A file containing reference hashes
```

