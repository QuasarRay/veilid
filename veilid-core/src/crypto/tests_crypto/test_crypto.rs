use super::*;

pub async fn test_aead(vcrypto: &AsyncCryptoSystemGuard<'_>) {
    info!("test_aead");

    let lorem_ipsum = Bytes::copy_from_slice(LOREM_IPSUM);

    let n1 = vcrypto.random_nonce().await;
    let _n2 = loop {
        let n = vcrypto.random_nonce().await;
        if n != n1 {
            break n;
        }
    };

    let ss1 = vcrypto.random_shared_secret().await;
    let _ss2 = loop {
        let ss = vcrypto.random_shared_secret().await;
        if ss != ss1 {
            break ss;
        }
    };

    assert!(
        vcrypto
            .decrypt_aead(lorem_ipsum.clone(), &n1, &ss1, None)
            .await
            .is_err(),
        "should fail authentication"
    );

    let body5 = vcrypto
        .encrypt_aead(lorem_ipsum.clone(), &n1, &ss1, None)
        .await
        .unwrap();
    let body6 = vcrypto
        .decrypt_aead(body5.clone(), &n1, &ss1, None)
        .await
        .unwrap();
    let body7 = vcrypto
        .encrypt_aead(lorem_ipsum.clone(), &n1, &ss1, None)
        .await
        .unwrap();
    assert_eq!(body6, lorem_ipsum.clone());
    assert_eq!(body5, body7);
}

pub async fn test_no_auth(vcrypto: &AsyncCryptoSystemGuard<'_>) {
    info!("test_no_auth");

    let lorem_ipsum = Bytes::copy_from_slice(LOREM_IPSUM);

    let n1 = vcrypto.random_nonce().await;
    let _n2 = loop {
        let n = vcrypto.random_nonce().await;
        if n != n1 {
            break n;
        }
    };

    let ss1 = vcrypto.random_shared_secret().await;
    let _ss2 = loop {
        let ss = vcrypto.random_shared_secret().await;
        if ss != ss1 {
            break ss;
        }
    };

    let body5 = Bytes::from(
        vcrypto
            .crypt_no_auth_unaligned(lorem_ipsum.clone(), &n1, &ss1)
            .await
            .unwrap(),
    );
    let body6 = vcrypto
        .crypt_no_auth_unaligned(body5.clone(), &n1, &ss1)
        .await
        .unwrap();
    let body7 = vcrypto
        .crypt_no_auth_unaligned(lorem_ipsum.clone(), &n1, &ss1)
        .await
        .unwrap();
    assert_eq!(body6, lorem_ipsum.clone());
    assert_eq!(body5, body7);

    let body5 = vcrypto
        .crypt_no_auth_aligned_8(lorem_ipsum.clone(), &n1, &ss1)
        .await
        .unwrap();
    let body6 = vcrypto
        .crypt_no_auth_aligned_8(Bytes::copy_from_slice(&body5), &n1, &ss1)
        .await
        .unwrap();
    let body7 = vcrypto
        .crypt_no_auth_aligned_8(lorem_ipsum.clone(), &n1, &ss1)
        .await
        .unwrap();
    assert_eq!(body6, lorem_ipsum.clone());
    assert_eq!(body5, body7);
}

pub async fn test_dh(vcrypto: &AsyncCryptoSystemGuard<'_>) {
    info!("test_dh");
    let (dht_key, dht_key_secret) = vcrypto.generate_keypair().await.into_split();
    assert!(vcrypto
        .validate_keypair(&dht_key, &dht_key_secret)
        .await
        .expect("should succeed"));
    let (dht_key2, dht_key_secret2) = vcrypto.generate_keypair().await.into_split();
    assert!(vcrypto
        .validate_keypair(&dht_key2, &dht_key_secret2)
        .await
        .expect("should succeed"));

    let r1 = vcrypto
        .compute_dh(&dht_key, &dht_key_secret2)
        .await
        .unwrap();
    let r2 = vcrypto
        .compute_dh(&dht_key2, &dht_key_secret)
        .await
        .unwrap();
    let r3 = vcrypto
        .compute_dh(&dht_key, &dht_key_secret2)
        .await
        .unwrap();
    let r4 = vcrypto
        .compute_dh(&dht_key2, &dht_key_secret)
        .await
        .unwrap();
    assert_eq!(r1, r2);
    assert_eq!(r3, r4);
    assert_eq!(r2, r3);
    trace!("dh: {:?}", r1);

    // test cache
    let r5 = vcrypto.cached_dh(&dht_key, &dht_key_secret2).await.unwrap();
    let r6 = vcrypto.cached_dh(&dht_key2, &dht_key_secret).await.unwrap();
    let r7 = vcrypto.cached_dh(&dht_key, &dht_key_secret2).await.unwrap();
    let r8 = vcrypto.cached_dh(&dht_key2, &dht_key_secret).await.unwrap();
    assert_eq!(r1, r5);
    assert_eq!(r2, r6);
    assert_eq!(r3, r7);
    assert_eq!(r4, r8);
    trace!("cached_dh: {:?}", r5);
}

pub async fn test_dh_rejects_all_zero_public_key(vcrypto: &AsyncCryptoSystemGuard<'_>) {
    let zero_pk = PublicKey::new(
        vcrypto.kind(),
        BarePublicKey::new(&vec![0u8; vcrypto.public_key_length()]),
    );
    let (_, secret) = vcrypto.generate_keypair().await.into_split();
    let result = vcrypto.compute_dh(&zero_pk, &secret).await;
    assert!(
        result.is_err(),
        "compute_dh must reject all-zero public key"
    );
}

pub async fn test_generation(vcrypto: &AsyncCryptoSystemGuard<'_>) {
    let b1 = vcrypto.random_bytes(32).await;
    let b2 = vcrypto.random_bytes(32).await;
    assert_ne!(b1, b2);
    assert_eq!(b1.len(), 32);
    assert_eq!(b2.len(), 32);
    let b3 = vcrypto.random_bytes(0).await;
    let b4 = vcrypto.random_bytes(0).await;
    assert_eq!(b3, b4);
    assert_eq!(b3.len(), 0);

    assert_ne!(vcrypto.default_salt_length(), 0);

    let password = Bytes::copy_from_slice(b"abc123".as_ref());
    let password2 = Bytes::copy_from_slice(b"abc124".as_ref());

    let salt = Bytes::copy_from_slice(b"qwerasdf".as_ref());
    let salt2 = Bytes::copy_from_slice(b"qwerasdg".as_ref());

    let pstr1 = vcrypto
        .hash_password(password.clone(), salt.clone())
        .await
        .unwrap();
    let pstr2 = vcrypto
        .hash_password(password.clone(), salt.clone())
        .await
        .unwrap();
    assert_eq!(pstr1, pstr2);
    let pstr3 = vcrypto
        .hash_password(password.clone(), salt2.clone())
        .await
        .unwrap();
    assert_ne!(pstr1, pstr3);
    let pstr4 = vcrypto
        .hash_password(password2.clone(), salt.clone())
        .await
        .unwrap();
    assert_ne!(pstr1, pstr4);
    let pstr5 = vcrypto
        .hash_password(password2.clone(), salt2.clone())
        .await
        .unwrap();
    assert_ne!(pstr3, pstr5);

    let short_salt = Bytes::copy_from_slice(b"qwe");
    let long_salt = Bytes::copy_from_slice(
        b"qwerqwerqwerqwerqwerqwerqwerqwerqwerqwerqwerqwerqwerqwerqwerqwerz",
    );

    let _ = vcrypto
        .hash_password(password.clone(), short_salt.clone())
        .await
        .expect_err("should reject short salt");
    let _ = vcrypto
        .hash_password(password.clone(), long_salt.clone())
        .await
        .expect_err("should reject long salt");

    assert!(vcrypto
        .verify_password(password.clone(), &pstr1)
        .await
        .unwrap());
    assert!(vcrypto
        .verify_password(password.clone(), &pstr2)
        .await
        .unwrap());
    assert!(vcrypto
        .verify_password(password.clone(), &pstr3)
        .await
        .unwrap());
    assert!(!vcrypto
        .verify_password(password.clone(), &pstr4)
        .await
        .unwrap());
    assert!(!vcrypto
        .verify_password(password.clone(), &pstr5)
        .await
        .unwrap());

    let ss1 = vcrypto
        .derive_shared_secret(password.clone(), salt.clone())
        .await;
    let ss2 = vcrypto
        .derive_shared_secret(password.clone(), salt.clone())
        .await;
    assert_eq!(ss1, ss2);
    let ss3 = vcrypto
        .derive_shared_secret(password.clone(), salt2.clone())
        .await;
    assert_ne!(ss1, ss3);
    let ss4 = vcrypto
        .derive_shared_secret(password2.clone(), salt.clone())
        .await;
    assert_ne!(ss1, ss4);
    let ss5 = vcrypto
        .derive_shared_secret(password2.clone(), salt2.clone())
        .await;
    assert_ne!(ss3, ss5);

    let _ = vcrypto
        .derive_shared_secret(password.clone(), short_salt.clone())
        .await
        .expect_err("should reject short salt");
    let _ = vcrypto
        .derive_shared_secret(password.clone(), long_salt.clone())
        .await
        .expect_err("should reject long salt");
}

pub async fn test_all() {
    let api = crypto_tests_startup().await;
    let crypto = api.crypto().unwrap();

    // Test versions
    for v in VALID_CRYPTO_KINDS {
        let vcrypto = crypto.get_async(v).unwrap();
        test_aead(&vcrypto).await;
        test_no_auth(&vcrypto).await;
        test_dh(&vcrypto).await;
        test_dh_rejects_all_zero_public_key(&vcrypto).await;
        test_generation(&vcrypto).await;
    }

    crypto_tests_shutdown(api.clone()).await;
    assert!(api.is_shutdown());
}
