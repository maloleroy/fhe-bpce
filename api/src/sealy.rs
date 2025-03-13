use sealy::*;

struct SealyFramework {
    encryptor: Encryptor,
    decryptor: Decryptor,
    evaluator: Evaluator,
}

fn create_sealy_framework() -> SealyFramework {
    let ctx = {
        let params = CKKSEncryptionParametersBuilder::new()
            .set_poly_modulus_degree(DegreeType::D8192)
            .set_coefficient_modulus(
                CoefficientModulusFactory::build(DegreeType::D8192, &[60, 50, 60]).unwrap(),
            )
            .build()
            .unwrap();
        Context::new(&params, false, SecurityLevel::default()).unwrap()
    };
    let (secret_key, public_key) = {
        let key_gen = KeyGenerator::new(&ctx).unwrap();
        (key_gen.secret_key(), key_gen.create_public_key())
    };
    let encoder = CKKSEncoder::new(&ctx, 1e13).unwrap();
    let encryptor = Encryptor::with_public_key(&ctx, &public_key).unwrap();
    let decryptor = Decryptor::new(&ctx, &secret_key).unwrap();
    let evaluator = CKKSEvaluator::new(&ctx).unwrap();
    let mut moy_e = {
        let zero_encoded = encoder.encode_f64(&[0.0]).unwrap();
        encryptor.encrypt(&zero_encoded).unwrap()
    };
    SealyFramework {
        encryptor,
        decryptor,
        evaluator,
    }
}
