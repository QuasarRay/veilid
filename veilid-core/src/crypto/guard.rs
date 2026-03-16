use core::marker::PhantomData;
use std::ops::Range;

use super::*;

/// Guard to access a particular cryptosystem
#[must_use]
pub struct CryptoSystemGuard<'a> {
    crypto_system: Arc<dyn CryptoSystem + Send + Sync>,
    _phantom: core::marker::PhantomData<&'a (dyn CryptoSystem + Send + Sync)>,
}

impl<'a> CryptoSystemGuard<'a> {
    pub(super) fn new(crypto_system: Arc<dyn CryptoSystem + Send + Sync>) -> Self {
        Self {
            crypto_system,
            _phantom: PhantomData,
        }
    }
    pub fn as_async(self) -> AsyncCryptoSystemGuard<'a> {
        AsyncCryptoSystemGuard { guard: self }
    }
    /// Get a clone of the inner Arc for use in blocking tasks
    pub(super) fn clone_arc(&self) -> Arc<dyn CryptoSystem + Send + Sync> {
        self.crypto_system.clone()
    }
}

impl core::ops::Deref for CryptoSystemGuard<'_> {
    type Target = dyn CryptoSystem + Send + Sync;

    fn deref(&self) -> &Self::Target {
        self.crypto_system.as_ref()
    }
}

/// Async cryptosystem guard to help break up heavy blocking operations
#[must_use]
pub struct AsyncCryptoSystemGuard<'a> {
    guard: CryptoSystemGuard<'a>,
}

impl AsyncCryptoSystemGuard<'_> {
    // Accessors
    pub fn kind(&self) -> CryptoKind {
        self.guard.kind()
    }
    #[must_use]
    pub fn crypto(&self) -> VeilidComponentGuard<'_, Crypto> {
        self.guard.crypto()
    }

    // Cached Operations
    pub async fn cached_dh(
        &self,
        key: &PublicKey,
        secret: &SecretKey,
    ) -> VeilidAPIResult<SharedSecret> {
        yielding(|| self.guard.cached_dh(key, secret)).await
    }

    // Generation
    pub async fn random_bytes(&self, len: usize) -> Bytes {
        yielding(|| self.guard.random_bytes(len).into()).await
    }

    pub async fn hash_password(&self, password: Bytes, salt: Bytes) -> VeilidAPIResult<String> {
        let cs = self.guard.clone_arc();
        let salt = salt.to_vec();
        cpu_yielding(move || cs.hash_password(&password, &salt)).await
    }
    pub async fn verify_password(
        &self,
        password: Bytes,
        password_hash: &str,
    ) -> VeilidAPIResult<bool> {
        let cs = self.guard.clone_arc();
        let password_hash = password_hash.to_string();
        cpu_yielding(move || cs.verify_password(&password, &password_hash)).await
    }
    pub async fn derive_shared_secret(
        &self,
        password: Bytes,
        salt: Bytes,
    ) -> VeilidAPIResult<SharedSecret> {
        yielding(|| self.guard.derive_shared_secret(&password, &salt)).await
    }
    pub async fn random_nonce(&self) -> Nonce {
        yielding(|| self.guard.random_nonce()).await
    }
    pub async fn random_shared_secret(&self) -> SharedSecret {
        yielding(|| self.guard.random_shared_secret()).await
    }
    pub async fn compute_dh(
        &self,
        key: &PublicKey,
        secret: &SecretKey,
    ) -> VeilidAPIResult<SharedSecret> {
        let cs = self.guard.clone_arc();
        let key = key.clone();
        let secret = secret.clone();
        cpu_yielding(move || cs.compute_dh(&key, &secret)).await
    }
    pub async fn generate_shared_secret(
        &self,
        key: &PublicKey,
        secret: &SecretKey,
        domain: Bytes,
    ) -> VeilidAPIResult<SharedSecret> {
        let dh = self.compute_dh(key, secret).await?;
        let data = [
            dh.ref_value().bytes().as_ref(),
            domain.as_ref(),
            VEILID_DOMAIN_API,
        ]
        .concat()
        .into();
        let hash = self.generate_hash(data).await;
        Ok(SharedSecret::new(
            hash.kind(),
            BareSharedSecret::new(&hash.into_value()),
        ))
    }

    pub async fn generate_keypair(&self) -> KeyPair {
        yielding(|| self.guard.generate_keypair()).await
    }

    pub async fn generate_hash(&self, data: Bytes) -> HashDigest {
        yielding(|| self.guard.generate_hash(&data)).await
    }

    pub async fn generate_hash_reader(
        &self,
        reader: &mut dyn std::io::Read,
    ) -> VeilidAPIResult<PublicKey> {
        yielding(|| self.guard.generate_hash_reader(reader)).await
    }

    // Validation
    #[must_use]
    pub fn shared_secret_length(&self) -> usize {
        self.guard.shared_secret_length()
    }
    #[must_use]
    pub fn nonce_length(&self) -> usize {
        self.guard.nonce_length()
    }
    #[must_use]
    pub fn hash_digest_length(&self) -> usize {
        self.guard.hash_digest_length()
    }
    #[must_use]
    pub fn public_key_length(&self) -> usize {
        self.guard.public_key_length()
    }
    #[must_use]
    pub fn secret_key_length(&self) -> usize {
        self.guard.secret_key_length()
    }
    #[must_use]
    pub fn signature_length(&self) -> usize {
        self.guard.signature_length()
    }
    #[must_use]
    pub fn aead_overhead(&self) -> usize {
        self.guard.aead_overhead()
    }
    #[must_use]
    pub fn default_salt_length(&self) -> usize {
        self.guard.default_salt_length()
    }
    pub fn check_shared_secret(&self, secret: &SharedSecret) -> VeilidAPIResult<()> {
        self.guard.check_shared_secret(secret)
    }
    pub fn check_nonce(&self, nonce: &Nonce) -> VeilidAPIResult<()> {
        self.guard.check_nonce(nonce)
    }
    pub fn check_hash_digest(&self, hash: &HashDigest) -> VeilidAPIResult<()> {
        self.guard.check_hash_digest(hash)
    }
    pub fn check_public_key(&self, key: &PublicKey) -> VeilidAPIResult<()> {
        self.guard.check_public_key(key)
    }
    pub fn check_secret_key(&self, key: &SecretKey) -> VeilidAPIResult<()> {
        self.guard.check_secret_key(key)
    }
    pub fn check_signature(&self, signature: &Signature) -> VeilidAPIResult<()> {
        self.guard.check_signature(signature)
    }
    pub async fn validate_keypair(
        &self,
        key: &PublicKey,
        secret: &SecretKey,
    ) -> VeilidAPIResult<bool> {
        yielding(|| self.guard.validate_keypair(key, secret)).await
    }

    pub async fn validate_hash(&self, data: Bytes, hash: &HashDigest) -> VeilidAPIResult<bool> {
        yielding(|| self.guard.validate_hash(&data, hash)).await
    }

    pub async fn validate_hash_reader(
        &self,
        reader: &mut dyn std::io::Read,
        hash: &HashDigest,
    ) -> VeilidAPIResult<bool> {
        yielding(|| self.guard.validate_hash_reader(reader, hash)).await
    }

    // Authentication
    pub async fn sign(
        &self,
        public_key: &PublicKey,
        secret: &SecretKey,
        data: Bytes,
    ) -> VeilidAPIResult<Signature> {
        let cs = self.guard.clone_arc();
        let public_key = public_key.clone();
        let secret = secret.clone();
        cpu_yielding(move || cs.sign(&public_key, &secret, &data)).await
    }

    pub async fn sign_in_place(
        &self,
        public_key: &PublicKey,
        secret: &SecretKey,
        mut data: BytesMut,
        range: Range<usize>,
        sig_idx: usize,
    ) -> VeilidAPIResult<BytesMut> {
        let cs = self.guard.clone_arc();
        let public_key = public_key.clone();
        let secret = secret.clone();
        cpu_yielding(move || {
            cs.sign_in_place(&public_key, &secret, &mut data, range, sig_idx)?;
            Ok(data)
        })
        .await
    }

    pub async fn verify(
        &self,
        public_key: &PublicKey,
        data: Bytes,
        signature: &Signature,
    ) -> VeilidAPIResult<bool> {
        let cs = self.guard.clone_arc();
        let public_key = public_key.clone();
        let signature = signature.clone();
        cpu_yielding(move || cs.verify(&public_key, &data, &signature)).await
    }

    pub async fn verify_in_place(
        &self,
        public_key: &PublicKey,
        data: Bytes,
        range: Range<usize>,
        sig_idx: usize,
    ) -> VeilidAPIResult<bool> {
        let cs = self.guard.clone_arc();
        let public_key = public_key.clone();
        cpu_yielding(move || cs.verify_in_place(&public_key, &data, range, sig_idx)).await
    }

    // AEAD Encrypt/Decrypt
    pub async fn decrypt_aead(
        &self,
        body: Bytes,
        nonce: &Nonce,
        shared_secret: &SharedSecret,
        associated_data: Option<Bytes>,
    ) -> VeilidAPIResult<Bytes> {
        let cs = self.guard.clone_arc();
        let nonce = nonce.clone();
        let shared_secret = shared_secret.clone();
        scaled_yielding(body.len(), 1024, 8192, move || {
            Ok(cs
                .decrypt_aead(&body, &nonce, &shared_secret, associated_data.as_deref())?
                .into())
        })
        .await
    }
    pub async fn decrypt_in_place_aead(
        &self,
        mut body: BytesMut,
        nonce: &Nonce,
        shared_secret: &SharedSecret,
        associated_data: Option<Bytes>,
    ) -> VeilidAPIResult<BytesMut> {
        let cs = self.guard.clone_arc();
        let nonce = nonce.clone();
        let shared_secret = shared_secret.clone();
        scaled_yielding(body.len(), 1024, 8192, move || {
            cs.decrypt_in_place_aead(
                &mut body,
                &nonce,
                &shared_secret,
                associated_data.as_deref(),
            )?;

            Ok(body)
        })
        .await
    }

    pub async fn encrypt_aead(
        &self,
        body: Bytes,
        nonce: &Nonce,
        shared_secret: &SharedSecret,
        associated_data: Option<Bytes>,
    ) -> VeilidAPIResult<Bytes> {
        let cs = self.guard.clone_arc();
        let nonce = nonce.clone();
        let shared_secret = shared_secret.clone();
        scaled_yielding(body.len(), 1024, 8192, move || {
            Ok(cs
                .encrypt_aead(&body, &nonce, &shared_secret, associated_data.as_deref())?
                .into())
        })
        .await
    }

    pub async fn encrypt_in_place_aead(
        &self,
        mut body: BytesMut,
        nonce: &Nonce,
        shared_secret: &SharedSecret,
        associated_data: Option<Bytes>,
    ) -> VeilidAPIResult<BytesMut> {
        let cs = self.guard.clone_arc();
        let nonce = nonce.clone();
        let shared_secret = shared_secret.clone();
        scaled_yielding(body.len(), 1024, 8192, move || {
            cs.encrypt_in_place_aead(
                &mut body,
                &nonce,
                &shared_secret,
                associated_data.as_deref(),
            )?;

            Ok(body)
        })
        .await
    }

    // NoAuth Encrypt/Decrypt
    pub async fn crypt_b2b_no_auth(
        &self,
        in_buf: Bytes,
        mut out_buf: BytesMut,
        out_idx: usize,
        nonce: &Nonce,
        shared_secret: &SharedSecret,
    ) -> VeilidAPIResult<BytesMut> {
        let cs = self.guard.clone_arc();
        let nonce = nonce.clone();
        let shared_secret = shared_secret.clone();
        scaled_yielding(in_buf.len(), 1024, 8192, move || {
            cs.crypt_b2b_no_auth(
                &in_buf,
                &mut out_buf[out_idx..out_idx + in_buf.len()],
                &nonce,
                &shared_secret,
            )?;
            Ok(out_buf)
        })
        .await
    }

    pub async fn crypt_in_place_no_auth(
        &self,
        mut body: BytesMut,
        range: Range<usize>,
        nonce: &Nonce,
        shared_secret: &SharedSecret,
    ) -> VeilidAPIResult<BytesMut> {
        let cs = self.guard.clone_arc();
        let nonce = nonce.clone();
        let shared_secret = shared_secret.clone();
        scaled_yielding(body.len(), 1024, 8192, move || {
            cs.crypt_in_place_no_auth(
                body.as_mut()
                    .get_mut(range)
                    .ok_or_else(|| VeilidAPIError::internal("range is out of bounds"))?,
                &nonce,
                &shared_secret,
            )?;
            Ok(body)
        })
        .await
    }

    pub async fn crypt_no_auth_aligned_8(
        &self,
        body: Bytes,
        nonce: &Nonce,
        shared_secret: &SharedSecret,
    ) -> VeilidAPIResult<Vec<u8>> {
        let cs = self.guard.clone_arc();
        let nonce = nonce.clone();
        let shared_secret = shared_secret.clone();
        scaled_yielding(body.len(), 1024, 8192, move || {
            cs.crypt_no_auth_aligned_8(&body, &nonce, &shared_secret)
        })
        .await
    }

    pub async fn crypt_no_auth_unaligned(
        &self,
        body: Bytes,
        nonce: &Nonce,
        shared_secret: &SharedSecret,
    ) -> VeilidAPIResult<Vec<u8>> {
        let cs = self.guard.clone_arc();
        let nonce = nonce.clone();
        let shared_secret = shared_secret.clone();
        scaled_yielding(body.len(), 1024, 8192, move || {
            cs.crypt_no_auth_unaligned(&body, &nonce, &shared_secret)
        })
        .await
    }
}
