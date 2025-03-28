fn main()
{
    // Specify the include path for OpenFHE
    println!("cargo:include=/home/fluteur/mylibs/include");

    // linking openFHE
    println!("cargo::rustc-link-arg=-L/home/fluteur/mylibs/lib");
    println!("cargo::rustc-link-arg=-lOPENFHEpke");
    println!("cargo::rustc-link-arg=-lOPENFHEbinfhe");
    println!("cargo::rustc-link-arg=-lOPENFHEcore");
    // linking OpenMP
    println!("cargo::rustc-link-arg=-fopenmp");
    // necessary to avoid LD_LIBRARY_PATH
    println!("cargo::rustc-link-arg=-Wl,-rpath=/home/fluteur/mylibs/lib");
}
