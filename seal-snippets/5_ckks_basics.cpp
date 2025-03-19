// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/util/numth.h"
#include "examples.h"

using namespace std;
using namespace seal;

struct ParameterSet
{
    size_t poly_modulus_degree;
    std::vector<int> bit_sizes;
    double scale;
};

const double DEFAULT_SCALE = pow(2.0, 10);

// never worked, for now
const ParameterSet PSET_LIGHT = { 2048, { 54 }, DEFAULT_SCALE };

// see 1_bfv_basics.cpp
const ParameterSet PSET_MODERATE = { 4096, { 36, 36, 36 }, DEFAULT_SCALE };

// by default  in this file
const ParameterSet PSET_HEAVY = { 8192, { 60, 40, 40, 60 }, DEFAULT_SCALE };

// by default  in this file
const ParameterSet PSET_MANY_MUL = { 8192, { 40, 40, 40, 40, 40 }, DEFAULT_SCALE };

struct FullContext
{
    SEALContext context;
    ParameterSet parameter_set;
};

FullContext get_default_full_context(size_t poly_modulus_degree)
{
    EncryptionParameters parms(scheme_type::ckks);
    auto coeff_modulus = CoeffModulus::BFVDefault(poly_modulus_degree);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(coeff_modulus);
    double scale = sqrt(static_cast<double>(coeff_modulus.back().value()));
    return { SEALContext{ parms }, { poly_modulus_degree, {}, scale } };
}

SEALContext get_seal_context(const ParameterSet &parameter_set)
{
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(parameter_set.poly_modulus_degree);
    if (parameter_set.bit_sizes.size() > 0)
    {
        parms.set_coeff_modulus(CoeffModulus::Create(parameter_set.poly_modulus_degree, parameter_set.bit_sizes));
    }
    else
    {
        parms.set_coeff_modulus(CoeffModulus::BFVDefault(parameter_set.poly_modulus_degree));
    }
    return SEALContext{ parms };
}

struct Tors
{
    Encryptor encryptor;
    Evaluator evaluator;
    Decryptor decryptor;
    const SEALContext &context;
    const ParameterSet &parameter_set;

    const CKKSEncoder encoder{ context };
};

struct Keys
{
    SecretKey secret_key;
    PublicKey public_key;
    RelinKeys relin_keys;
    GaloisKeys gal_keys;
};

Keys get_keys(const SEALContext &context)
{
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);
    return { secret_key, public_key, relin_keys, gal_keys };
}

Tors get_tors(const SEALContext &context, const ParameterSet &parameter_set)
{
    auto keys = get_keys(context);
    return { Encryptor{ context, keys.public_key }, Evaluator{ context }, Decryptor{ context, keys.secret_key },
             context, parameter_set };
}

Ciphertext to_ciphertext(const double &x, const Tors &tors)
{
    Plaintext plaintext;
    tors.encoder.encode(x, tors.parameter_set.scale, plaintext);
    Ciphertext ciphertext;
    tors.encryptor.encrypt(plaintext, ciphertext);
    return ciphertext;
}

double to_double(const Ciphertext &cipher, Tors &tors)
{
    Plaintext plaintext;
    std::vector<double> v;

    tors.decryptor.decrypt(cipher, plaintext);
    tors.encoder.decode(plaintext, v);
    return v[0];
}

double same(const double &x, Tors &tors)
{
    return to_double(to_ciphertext(x, tors), tors);
}

Ciphertext add_ciphers(const Ciphertext &cipher_a, const Ciphertext &cipher_b, const Tors &tors)
{
    Ciphertext cipher_result;
    tors.evaluator.add(cipher_a, cipher_b, cipher_result);
    return cipher_result;
}

Ciphertext multiply_ciphers(const Ciphertext &cipher_a, const Ciphertext &cipher_b, const Tors &tors)
{
    Ciphertext cipher_result;
    tors.evaluator.multiply(cipher_a, cipher_b, cipher_result);
    return cipher_result;
}

double add_doubles(const double &a, const double &b, Tors &tors)
{
    return to_double(add_ciphers(to_ciphertext(a, tors), to_ciphertext(b, tors), tors), tors);
}

double sum(const vector<double> values, Tors &tors)
{
    if (values.size() == 0)
    {
        return 0;
    }
    Ciphertext sum = to_ciphertext(values[0], tors);
    for (size_t i = 1; i < values.size(); i++)
    {
        tors.evaluator.add_inplace(sum, to_ciphertext(values[i], tors));
    }
    return to_double(sum, tors);
}

pair<double, double> sum_random_doubles(size_t count, Tors &tors)
{
    double real_sum = 0;
    std::random_device rd;
    const double lower_bound = 0.0;
    const double upper_bound = 10.0;
    std::uniform_real_distribution<double> unif(lower_bound, upper_bound);
    std::default_random_engine re(rd());

    Ciphertext sum = to_ciphertext(0., tors);
    for (size_t i = 0; i < count; i++)
    {
        double random_double = unif(re);
        real_sum += random_double;
        tors.evaluator.add_inplace(sum, to_ciphertext(random_double, tors));
    }
    return { to_double(sum, tors), real_sum };
}

pair<double, double> sum_random_doubles_asynchronous(size_t count, Tors &tors)
{
    const size_t num_threads = std::thread::hardware_concurrency(); // Get number of CPU threads
    size_t chunk_size = count / num_threads;

    std::vector<std::thread> threads;
    std::vector<double> real_sums(num_threads, 0.0);
    std::vector<Ciphertext> encrypted_sums(num_threads, to_ciphertext(0.0, tors));

    std::mutex tors_mutex; // Protect access to tors

    auto worker = [&](size_t thread_id, size_t start, size_t end) {
        std::random_device rd;
        std::default_random_engine re(rd());
        std::uniform_real_distribution<double> unif(0.0, 10.0);

        double local_real_sum = 0.0;
        Ciphertext local_enc_sum = to_ciphertext(0.0, tors);

        for (size_t i = start; i < end; i++)
        {
            double random_double = unif(re);
            local_real_sum += random_double;
            tors.evaluator.add_inplace(local_enc_sum, to_ciphertext(random_double, tors));
        }

        real_sums[thread_id] = local_real_sum;

        std::lock_guard<std::mutex> lock(tors_mutex);
        encrypted_sums[thread_id] = local_enc_sum;
    };

    // Launch threads
    for (size_t i = 0; i < num_threads; i++)
    {
        size_t start = i * chunk_size;
        size_t end = (i == num_threads - 1) ? count : (i + 1) * chunk_size;
        threads.emplace_back(worker, i, start, end);
    }

    // Join threads
    for (auto &t : threads)
    {
        t.join();
    }

    // Aggregate results
    double total_real_sum = 0.0;
    Ciphertext total_enc_sum = to_ciphertext(0.0, tors);

    for (size_t i = 0; i < num_threads; i++)
    {
        total_real_sum += real_sums[i];
        tors.evaluator.add_inplace(total_enc_sum, encrypted_sums[i]);
    }

    return { to_double(total_enc_sum, tors), total_real_sum };
}

struct Benchmark
{
    const size_t poly_modulus_degree;
    const size_t count;
    const bool asynchronous;
    const double upper_bound;
    double error_ratio;
    double elapsed_time;
};

void perform_benchmark(Benchmark &benchmark)
{
    auto [context, parameter_set] = get_default_full_context(benchmark.poly_modulus_degree);
    Tors tors = get_tors(context, parameter_set);

    // testing execution time of sum_random_doubles
    const size_t N = 10000;
    auto start = std::chrono::high_resolution_clock::now();
    if (benchmark.asynchronous)
    {
        auto [sum, real_sum] = sum_random_doubles_asynchronous(benchmark.count, tors);
        benchmark.error_ratio = abs(sum - real_sum) / real_sum;
    }
    else
    {
        auto [sum, real_sum] = sum_random_doubles(benchmark.count, tors);
        benchmark.error_ratio = abs(sum - real_sum) / real_sum;
    }
    auto finish = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = finish - start;
    benchmark.elapsed_time = elapsed.count();
}

void print_benchmark_row(const Benchmark &benchmark)
{
    const string splitter = " | ";
    cout << benchmark.poly_modulus_degree << splitter << benchmark.count << splitter << benchmark.asynchronous
         << splitter << benchmark.upper_bound << splitter << benchmark.error_ratio << splitter << benchmark.elapsed_time
         << endl;
}

void my_main()
{
    cout << "poly_modulus_degree | count | asynchronous | upper_bound | error_ratio | elapsed_time" << endl;
    for (size_t poly_modulus_degree : { 4096, 8192 })
    {
        for (size_t count : { 50000, 100000 })
        {
            for (bool asynchronous : { false, true })
            {
                for (double upper_bound : { 10. })
                {
                    Benchmark benchmark{ poly_modulus_degree, count, asynchronous, upper_bound, 0., 0. };
                    try
                    {
                        perform_benchmark(benchmark);
                        print_benchmark_row(benchmark);
                    }
                    catch (const std::exception &e)
                    {
                        cout << "Error: " << e.what() << endl;
                        continue;
                    }
                }
            }
        }
    }
}

void debug_product()
{
    auto [context, parameter_set] = get_default_full_context(4096);
    Tors tors = get_tors(context, parameter_set);

    double a = 1.0;
    double b = 1.0;
    double c = 2.0;
    double d = 0.0;

    cout << "Scale: " << tors.parameter_set.scale << endl;

    Ciphertext cipher_a = to_ciphertext(a, tors);
    Ciphertext cipher_b = to_ciphertext(b, tors);
    Ciphertext cipher_c = to_ciphertext(c, tors);
    Ciphertext cipher_d = to_ciphertext(d, tors);

    Ciphertext cipher_ab = multiply_ciphers(cipher_a, cipher_b, tors);
    Ciphertext cipher_cd = multiply_ciphers(cipher_c, cipher_d, tors);

    Ciphertext cipher_ab_plus_cd = add_ciphers(cipher_ab, cipher_cd, tors);

    double decrypted_ab_plus_cd = to_double(cipher_ab_plus_cd, tors);

    double ab_plus_cd = a * b + c * d;

    cout << "Decrypted: " << decrypted_ab_plus_cd << endl;
    cout << "Real: " << ab_plus_cd << endl;
}

template <size_t N>
constexpr std::array<uint64_t, N> chebyshev_coefficients()
{
    std::array<std::array<uint64_t, N>, N> coeffs{};
    coeffs[0][0] = 1;
    if (N > 1)
    {
        coeffs[1][1] = 1;
    }

    for (size_t i = 2; i < N; ++i)
    {
        for (size_t j = 0; j < i; ++j)
        {
            coeffs[i][j + 1] += 2 * coeffs[i - 1][j];
            if (j < N - 1)
            {
                coeffs[i][j] -= coeffs[i - 2][j];
            }
        }
    }

    return coeffs[N - 1];
}

void debug_skibidi()
{
    auto [context, parameter_set] = get_default_full_context(4096);
    Tors tors = get_tors(context, parameter_set);
    static const double A1 = 1.211324865405185;
    static const double A3 = -0.84529946162075;

    auto a1 = to_ciphertext(A1, tors);
    auto a3 = to_ciphertext(A3, tors);

    double x_plain = 3.;
    auto x = to_ciphertext(x_plain, tors);

    auto x2 = multiply_ciphers(x, x, tors);

    // Pre-product of a3 and x2
    tors.evaluator.rescale_to_next_inplace(x2);
    tors.evaluator.rescale_to_next_inplace(a3);

    auto a3x2 = multiply_ciphers(a3, x2, tors);

    auto a1_plus_a3x2 = add_ciphers(a3x2, a1, tors);

    // Rescaling before the product of a1_plus_a3x2 and x
    tors.evaluator.rescale_to_next_inplace(a1_plus_a3x2);
    tors.evaluator.rescale_to_next_inplace(x);

    auto result = multiply_ciphers(a1_plus_a3x2, x, tors);

    cout << "Decrypted: " << to_double(result, tors) << endl;
}

constexpr double PI = 3.141592653589793;

/// Approximate sin(x) using a Taylor series expansion (valid for small x)
constexpr double sin_taylor(double x)
{
    double x2 = x * x;
    return x * (1.0 - x2 / 6.0 + (x2 * x2) / 120.0 - (x2 * x2 * x2) / 5040.0);
}

/// Computes the denominator for the Lagrange basis polynomial
constexpr double denominator(size_t i, size_t n)
{
    double i_theta = (i * PI) / (n + 3.0);
    return sin_taylor(i_theta);
}

template <size_t N>
constexpr std::array<double, N> pbas_coefficients()
{
    std::array<double, N> coeffs{};
    for (size_t i = 1; i <= N; ++i)
    {
        double den = denominator(i, N);
        double prod = 1.0;
        for (size_t j = 1; j <= (N + 1) / 2; ++j)
        {
            if (j != i)
            {
                double num = std::pow(denominator(j, N), 2);
                double den_sq = std::pow(den, 2) - num;
                prod *= den_sq;
            }
        }
        coeffs[i - 1] = 1.0 / den / prod;
    }
    return coeffs;
}

void debug_sign_small()
{
    constexpr size_t N = 3;
    constexpr auto COEFFS = pbas_coefficients<N>();

    auto [context, parameter_set] = get_default_full_context(4096);
    Tors tors = get_tors(context, parameter_set);

    auto result = to_ciphertext(0., tors);
    auto x_pow_i = to_ciphertext(1., tors);

    for (auto i = 0; i < N; i++)
    {
        auto term = to_ciphertext(COEFFS[i], tors);
        term = multiply_ciphers(term, x_pow_i, tors);
        result = add_ciphers(result, term, tors);
        if (i != N - 1)
        {
            x_pow_i = multiply_ciphers(x_pow_i, to_ciphertext(1., tors), tors);
            tors.evaluator.rescale_to_next_inplace(x_pow_i);
        }
        tors.evaluator.rescale_to_next_inplace(result);
    }
    cout << "Decrypted: " << to_double(result, tors) << endl;
}

void debug_sign()
{
    constexpr size_t N = 3;
    constexpr auto COEFFS = chebyshev_coefficients<N>();

    auto [context, parameter_set] = get_default_full_context(4096);
    Tors tors = get_tors(context, parameter_set);

    auto result = to_ciphertext(0., tors);
    auto x_pow_i = to_ciphertext(1., tors);

    for (auto i = 0; i < N; i++)
    {
        auto term = to_ciphertext(COEFFS[i], tors);
        cout << "term [after init]: " << term.scale() << endl;
        cout << "[before term * x_pow]: " << term.scale() << " * " << x_pow_i.scale() << " = "
             << term.scale() * x_pow_i.scale() << endl;
        term = multiply_ciphers(term, x_pow_i, tors);
        cout << "term [after *]: " << term.scale() << endl;
        // print the scale of term and result
        cout << "Scale of termuwu: " << term.scale() << endl;
        cout << "Scale of resultuwu: " << result.scale() << endl;
        result = multiply_ciphers(result, to_ciphertext(1., tors), tors);
        cout << "term [before +result]: " << term.scale() << endl;
        cout << "result [before +term]: " << result.scale() << endl;
        result = add_ciphers(result, term, tors);
        cout << "result [after +]: " << result.scale() << endl;
        if (i != N - 1)
        {
            x_pow_i = multiply_ciphers(x_pow_i, to_ciphertext(1., tors), tors);
            cout << "x_pow_i [after *]: " << x_pow_i.scale() << endl;
            tors.evaluator.rescale_to_next_inplace(x_pow_i);
            cout << "x_pow_i [after =]: " << x_pow_i.scale() << endl;
        }
        cout << "result [before =]: " << result.scale() << endl;
        tors.evaluator.rescale_to_next_inplace(result);
        cout << "result [after =]: " << result.scale() << endl;
    }
    cout << "Decrypted: " << to_double(result, tors) << endl;
}

void example_ckks_basics()
{
    // print_example_banner("Example: CKKS Basics");

    debug_sign();
    // my_main();
    return;

    /*
    In this example we demonstrate evaluating a polynomial function

        PI*x^3 + 0.4*x + 1

    on encrypted floating-point input data x for a set of 4096 equidistant points
    in the interval [0, 1]. This example demonstrates many of the main features
    of the CKKS scheme, but also the challenges in using it.

    We start by setting up the CKKS scheme.
    */
    EncryptionParameters parms(scheme_type::ckks);

    /*
    We saw in `2_encoders.cpp' that multiplication in CKKS causes scales
    in ciphertexts to grow. The scale of any ciphertext must not get too close
    to the total size of coeff_modulus, or else the ciphertext simply runs out of
    room to store the scaled-up plaintext. The CKKS scheme provides a `rescale'
    functionality that can reduce the scale, and stabilize the scale expansion.

    Rescaling is a kind of modulus switch operation (recall `3_levels.cpp').
    As modulus switching, it removes the last of the primes from coeff_modulus,
    but as a side-effect it scales down the ciphertext by the removed prime.
    Usually we want to have perfect control over how the scales are changed,
    which is why for the CKKS scheme it is more common to use carefully selected
    primes for the coeff_modulus.

    More precisely, suppose that the scale in a CKKS ciphertext is S, and the
    last prime in the current coeff_modulus (for the ciphertext) is P. Rescaling
    to the next level changes the scale to S/P, and removes the prime P from the
    coeff_modulus, as usual in modulus switching. The number of primes limits
    how many rescalings can be done, and thus limits the multiplicative depth of
    the computation.

    It is possible to choose the initial scale freely. One good strategy can be
    to is to set the initial scale S and primes P_i in the coeff_modulus to be
    very close to each other. If ciphertexts have scale S before multiplication,
    they have scale S^2 after multiplication, and S^2/P_i after rescaling. If all
    P_i are close to S, then S^2/P_i is close to S again. This way we stabilize the
    scales to be close to S throughout the computation. Generally, for a circuit
    of depth D, we need to rescale D times, i.e., we need to be able to remove D
    primes from the coefficient modulus. Once we have only one prime left in the
    coeff_modulus, the remaining prime must be larger than S by a few bits to
    preserve the pre-decimal-point value of the plaintext.

    Therefore, a generally good strategy is to choose parameters for the CKKS
    scheme as follows:

        (1) Choose a 60-bit prime as the first prime in coeff_modulus. This will
            give the highest precision when decrypting;
        (2) Choose another 60-bit prime as the last element of coeff_modulus, as
            this will be used as the special prime and should be as large as the
            largest of the other primes;
        (3) Choose the intermediate primes to be close to each other.

    We use CoeffModulus::Create to generate primes of the appropriate size. Note
    that our coeff_modulus is 200 bits total, which is below the bound for our
    poly_modulus_degree: CoeffModulus::MaxBitCount(8192) returns 218.
    */

    parms.set_poly_modulus_degree(PSET_HEAVY.poly_modulus_degree);

    // for poly_modulus_degree = 8192, it was { 60, 40, 40, 60 }
    //  sum is 16 + 10 + 10 + 16 = 52 which is less than seal_he_std_parms_128_tc(2048) = 54
    // Non-failing bit sizes are:
    // 14, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37
    // 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60
    parms.set_coeff_modulus(CoeffModulus::Create(PSET_HEAVY.poly_modulus_degree, PSET_HEAVY.bit_sizes));

    /*
    We choose the initial scale to be 2^40. At the last level, this leaves us
    60-40=20 bits of precision before the decimal point, and enough (roughly
    10-20 bits) of precision after the decimal point. Since our intermediate
    primes are 40 bits (in fact, they are very close to 2^40), we can achieve
    scale stabilization as described above.

    In the modified version, this leaves us with 52-32=20 bits of precision
    */
    double scale = pow(2.0, 40);

    SEALContext context(parms);
    print_parameters(context);
    cout << endl;

    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;

    vector<double> input;
    input.reserve(slot_count);
    double curr_point = 0;
    double step_size = 1.0 / (static_cast<double>(slot_count) - 1);
    for (size_t i = 0; i < slot_count; i++)
    {
        input.push_back(curr_point);
        curr_point += step_size;
    }
    cout << "Input vector: " << endl;
    print_vector(input, 3, 7);

    cout << "Evaluating polynomial PI*x^3 + 0.4x + 1 ..." << endl;

    /*
    We create plaintexts for PI, 0.4, and 1 using an overload of CKKSEncoder::encode
    that encodes the given floating-point value to every slot in the vector.
    */
    Plaintext plain_coeff3, plain_coeff1, plain_coeff0;
    encoder.encode(3.14159265, scale, plain_coeff3);
    encoder.encode(0.4, scale, plain_coeff1);
    encoder.encode(1.0, scale, plain_coeff0);

    Plaintext x_plain;
    print_line(__LINE__);
    cout << "Encode input vectors." << endl;
    encoder.encode(input, scale, x_plain);
    Ciphertext x1_encrypted;
    encryptor.encrypt(x_plain, x1_encrypted);

    /*
    To compute x^3 we first compute x^2 and relinearize. However, the scale has
    now grown to 2^80.
    */
    Ciphertext x3_encrypted;
    print_line(__LINE__);
    cout << "Compute x^2 and relinearize:" << endl;
    evaluator.square(x1_encrypted, x3_encrypted);
    evaluator.relinearize_inplace(x3_encrypted, relin_keys);
    cout << "    + Scale of x^2 before rescale: " << log2(x3_encrypted.scale()) << " bits" << endl;

    /*
    Now rescale; in addition to a modulus switch, the scale is reduced down by
    a factor equal to the prime that was switched away (40-bit prime). Hence, the
    new scale should be close to 2^40. Note, however, that the scale is not equal
    to 2^40: this is because the 40-bit prime is only close to 2^40.
    */
    print_line(__LINE__);
    cout << "Rescale x^2." << endl;
    evaluator.rescale_to_next_inplace(x3_encrypted);
    cout << "    + Scale of x^2 after rescale: " << log2(x3_encrypted.scale()) << " bits" << endl;

    /*
    Now x3_encrypted is at a different level than x1_encrypted, which prevents us
    from multiplying them to compute x^3. We could simply switch x1_encrypted to
    the next parameters in the modulus switching chain. However, since we still
    need to multiply the x^3 term with PI (plain_coeff3), we instead compute PI*x
    first and multiply that with x^2 to obtain PI*x^3. To this end, we compute
    PI*x and rescale it back from scale 2^80 to something close to 2^40.
    */
    print_line(__LINE__);
    cout << "Compute and rescale PI*x." << endl;
    Ciphertext x1_encrypted_coeff3;
    evaluator.multiply_plain(x1_encrypted, plain_coeff3, x1_encrypted_coeff3);
    cout << "    + Scale of PI*x before rescale: " << log2(x1_encrypted_coeff3.scale()) << " bits" << endl;
    evaluator.rescale_to_next_inplace(x1_encrypted_coeff3);
    cout << "    + Scale of PI*x after rescale: " << log2(x1_encrypted_coeff3.scale()) << " bits" << endl;

    /*
    Since x3_encrypted and x1_encrypted_coeff3 have the same exact scale and use
    the same encryption parameters, we can multiply them together. We write the
    result to x3_encrypted, relinearize, and rescale. Note that again the scale
    is something close to 2^40, but not exactly 2^40 due to yet another scaling
    by a prime. We are down to the last level in the modulus switching chain.
    */
    print_line(__LINE__);
    cout << "Compute, relinearize, and rescale (PI*x)*x^2." << endl;
    evaluator.multiply_inplace(x3_encrypted, x1_encrypted_coeff3);
    evaluator.relinearize_inplace(x3_encrypted, relin_keys);
    cout << "    + Scale of PI*x^3 before rescale: " << log2(x3_encrypted.scale()) << " bits" << endl;
    evaluator.rescale_to_next_inplace(x3_encrypted);
    cout << "    + Scale of PI*x^3 after rescale: " << log2(x3_encrypted.scale()) << " bits" << endl;

    /*
    Next we compute the degree one term. All this requires is one multiply_plain
    with plain_coeff1. We overwrite x1_encrypted with the result.
    */
    print_line(__LINE__);
    cout << "Compute and rescale 0.4*x." << endl;
    evaluator.multiply_plain_inplace(x1_encrypted, plain_coeff1);
    cout << "    + Scale of 0.4*x before rescale: " << log2(x1_encrypted.scale()) << " bits" << endl;
    evaluator.rescale_to_next_inplace(x1_encrypted);
    cout << "    + Scale of 0.4*x after rescale: " << log2(x1_encrypted.scale()) << " bits" << endl;

    /*
    Now we would hope to compute the sum of all three terms. However, there is
    a serious problem: the encryption parameters used by all three terms are
    different due to modulus switching from rescaling.

    Encrypted addition and subtraction require that the scales of the inputs are
    the same, and also that the encryption parameters (parms_id) match. If there
    is a mismatch, Evaluator will throw an exception.
    */
    cout << endl;
    print_line(__LINE__);
    cout << "Parameters used by all three terms are different." << endl;
    cout << "    + Modulus chain index for x3_encrypted: "
         << context.get_context_data(x3_encrypted.parms_id())->chain_index() << endl;
    cout << "    + Modulus chain index for x1_encrypted: "
         << context.get_context_data(x1_encrypted.parms_id())->chain_index() << endl;
    cout << "    + Modulus chain index for plain_coeff0: "
         << context.get_context_data(plain_coeff0.parms_id())->chain_index() << endl;
    cout << endl;

    /*
    Let us carefully consider what the scales are at this point. We denote the
    primes in coeff_modulus as P_0, P_1, P_2, P_3, in this order. P_3 is used as
    the special modulus and is not involved in rescalings. After the computations
    above the scales in ciphertexts are:

        - Product x^2 has scale 2^80 and is at level 2;
        - Product PI*x has scale 2^80 and is at level 2;
        - We rescaled both down to scale 2^80/P_2 and level 1;
        - Product PI*x^3 has scale (2^80/P_2)^2;
        - We rescaled it down to scale (2^80/P_2)^2/P_1 and level 0;
        - Product 0.4*x has scale 2^80;
        - We rescaled it down to scale 2^80/P_2 and level 1;
        - The contant term 1 has scale 2^40 and is at level 2.

    Although the scales of all three terms are approximately 2^40, their exact
    values are different, hence they cannot be added together.
    */
    print_line(__LINE__);
    cout << "The exact scales of all three terms are different:" << endl;
    ios old_fmt(nullptr);
    old_fmt.copyfmt(cout);
    cout << fixed << setprecision(10);
    cout << "    + Exact scale in PI*x^3: " << x3_encrypted.scale() << endl;
    cout << "    + Exact scale in  0.4*x: " << x1_encrypted.scale() << endl;
    cout << "    + Exact scale in      1: " << plain_coeff0.scale() << endl;
    cout << endl;
    cout.copyfmt(old_fmt);

    /*
    There are many ways to fix this problem. Since P_2 and P_1 are really close
    to 2^40, we can simply "lie" to Microsoft SEAL and set the scales to be the
    same. For example, changing the scale of PI*x^3 to 2^40 simply means that we
    scale the value of PI*x^3 by 2^120/(P_2^2*P_1), which is very close to 1.
    This should not result in any noticeable error.

    Another option would be to encode 1 with scale 2^80/P_2, do a multiply_plain
    with 0.4*x, and finally rescale. In this case we would need to additionally
    make sure to encode 1 with appropriate encryption parameters (parms_id).

    In this example we will use the first (simplest) approach and simply change
    the scale of PI*x^3 and 0.4*x to 2^40.
    */
    print_line(__LINE__);
    cout << "Normalize scales to 2^40." << endl;
    x3_encrypted.scale() = pow(2.0, 40);
    x1_encrypted.scale() = pow(2.0, 40);

    /*
    We still have a problem with mismatching encryption parameters. This is easy
    to fix by using traditional modulus switching (no rescaling). CKKS supports
    modulus switching just like the BFV scheme, allowing us to switch away parts
    of the coefficient modulus when it is simply not needed.
    */
    print_line(__LINE__);
    cout << "Normalize encryption parameters to the lowest level." << endl;
    parms_id_type last_parms_id = x3_encrypted.parms_id();
    evaluator.mod_switch_to_inplace(x1_encrypted, last_parms_id);
    evaluator.mod_switch_to_inplace(plain_coeff0, last_parms_id);

    /*
    All three ciphertexts are now compatible and can be added.
    */
    print_line(__LINE__);
    cout << "Compute PI*x^3 + 0.4*x + 1." << endl;
    Ciphertext encrypted_result;
    evaluator.add(x3_encrypted, x1_encrypted, encrypted_result);
    evaluator.add_plain_inplace(encrypted_result, plain_coeff0);

    /*
    First print the true result.
    */
    Plaintext plain_result;
    print_line(__LINE__);
    cout << "Decrypt and decode PI*x^3 + 0.4x + 1." << endl;
    cout << "    + Expected result:" << endl;
    vector<double> true_result;
    for (size_t i = 0; i < input.size(); i++)
    {
        double x = input[i];
        true_result.push_back((3.14159265 * x * x + 0.4) * x + 1);
    }
    print_vector(true_result, 3, 7);

    /*
    Decrypt, decode, and print the result.
    */
    decryptor.decrypt(encrypted_result, plain_result);
    vector<double> result;
    encoder.decode(plain_result, result);
    cout << "    + Computed result ...... Correct." << endl;
    print_vector(result, 3, 7);

    /*
    While we did not show any computations on complex numbers in these examples,
    the CKKSEncoder would allow us to have done that just as easily. Additions
    and multiplications of complex numbers behave just as one would expect.
    */
}
