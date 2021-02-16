package io.jsonwebtoken.impl;

import io.jsonwebtoken.JweBuilder;
import io.jsonwebtoken.JweHeader;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.impl.lang.Services;
import io.jsonwebtoken.impl.security.DefaultAesEncryptionRequest;
import io.jsonwebtoken.impl.security.DefaultEncryptKeyRequest;
import io.jsonwebtoken.impl.security.DefaultKeyRequest;
import io.jsonwebtoken.impl.security.EncryptedKeyAlgorithm;
import io.jsonwebtoken.io.SerializationException;
import io.jsonwebtoken.io.Serializer;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.AeadIvEncryptionResult;
import io.jsonwebtoken.security.AeadRequest;
import io.jsonwebtoken.security.AeadSymmetricEncryptionAlgorithm;
import io.jsonwebtoken.security.KeyAlgorithm;
import io.jsonwebtoken.security.KeyAlgorithms;
import io.jsonwebtoken.security.KeyRequest;
import io.jsonwebtoken.security.KeyResult;

import javax.crypto.SecretKey;
import java.security.Key;

public class DefaultJweBuilder extends DefaultJwtBuilder<JweBuilder> implements JweBuilder {

    private AeadSymmetricEncryptionAlgorithm<byte[]> enc; // MUST be AEAD per https://tools.ietf.org/html/rfc7516#section-4.1.2

    private KeyAlgorithm<Key, KeyRequest<Key>> alg;

    private Key key;

    @Override
    public JweBuilder setPayload(String payload) {
        Assert.hasLength(payload, "payload cannot be null or empty."); //allowed for JWS, but not JWE
        return super.setPayload(payload);
    }

    @Override
    public JweBuilder encryptWith(AeadSymmetricEncryptionAlgorithm<byte[]> enc) {
        this.enc = Assert.notNull(enc, "EncryptionAlgorithm cannot be null.");
        Assert.hasText(enc.getName(), "EncryptionAlgorithm name cannot be null or empty.");
        return this;
    }

    @Override
    public JweBuilder withKey(SecretKey key) {
        return withKeyFrom(key, KeyAlgorithms.DIRECT);
    }

    @SuppressWarnings("unchecked")
    @Override
    public <K extends Key, R extends KeyRequest<K>> JweBuilder withKeyFrom(K key, KeyAlgorithm<K, R> alg) {
        this.alg = (KeyAlgorithm<Key, KeyRequest<Key>>)Assert.notNull(alg, "KeyAlgorithm cannot be null.");
        Assert.hasText(alg.getName(), "KeyAlgorithm name cannot be null or empty.");
        this.key = Assert.notNull(key, "key cannot be null.");
        return this;
    }

    @Override
    public String compact() {

        if (!Strings.hasLength(payload) && Collections.isEmpty(claims)) {
            String msg = "Either 'claims' or a non-empty 'payload' must be specified.";
            throw new IllegalStateException(msg);
        }

        if (Strings.hasLength(payload) && !Collections.isEmpty(claims)) {
            throw new IllegalStateException("Both 'payload' and 'claims' cannot both be specified. Choose either one.");
        }

        Assert.state(alg != null, "keyAlgorithm is required.");
        Assert.state(enc != null, "encryptionAlgorithm is required.");

        if (this.serializer == null) { // try to find one based on the services available
            //noinspection unchecked
            this.serializer = Services.loadFirst(Serializer.class);
        }

        header = ensureHeader();

        JweHeader jweHeader;
        if (header instanceof JweHeader) {
            jweHeader = (JweHeader) header;
        } else {
            //noinspection unchecked
            header = jweHeader = new DefaultJweHeader(header);
        }

        byte[] plaintext;
        try {
            plaintext = this.payload != null ? payload.getBytes(Strings.UTF_8) : this.serializer.serialize(claims);
        } catch (SerializationException e) {
            throw new IllegalArgumentException("Unable to serialize claims to json: " + e.getMessage(), e);
        }

        if (compressionCodec != null) {
            plaintext = compressionCodec.compress(plaintext);
            jweHeader.setCompressionAlgorithm(compressionCodec.getAlgorithmName());
        }

        KeyRequest<Key> keyRequest;
        if (alg instanceof EncryptedKeyAlgorithm) {
            SecretKey cek = enc.generateKey();
            keyRequest = new DefaultEncryptKeyRequest<>(this.key, cek, this.provider, this.secureRandom);
        } else {
            keyRequest = new DefaultKeyRequest<>(this.key);
        }

        KeyResult keyResult = Assert.notNull(alg.getKey(keyRequest), "KeyAlgorithm must return a KeyResult.");
        SecretKey cek = Assert.notNull(keyResult.getKey(), "KeyResult must return a content encryption key.");
        byte[] encryptedCek = Assert.notNull(keyResult.getEncryptedKey(), "KeyResult must return an encrypted key byte array, even if empty.");

        jweHeader.setEncryptionAlgorithm(enc.getName());
        jweHeader.setAlgorithm(alg.getName());
        jweHeader.putAll(keyResult.getHeaderParams());

        byte[] headerBytes;
        try {
            headerBytes = this.serializer.serialize(jweHeader);
        } catch (Exception e) {
            String msg = "Unable to serialize header to json: " + e.getMessage();
            throw new SerializationException(msg , e);
        }

        AeadRequest<byte[], SecretKey> encRequest =
            new DefaultAesEncryptionRequest<>(plaintext, cek, provider, secureRandom, headerBytes);
        AeadIvEncryptionResult encResult = enc.encrypt(encRequest);

        byte[] iv = Assert.notEmpty(encResult.getInitializationVector(), "EncryptionResult must have a non-empty initialization vector.");
        byte[] ciphertext = Assert.notEmpty(encResult.getCiphertext(), "EncryptionResult must have non-empty ciphertext.");
        byte[] tag = Assert.notEmpty(encResult.getAuthenticationTag(), "EncryptionResult must have a non-empty authentication tag.");

        String base64UrlEncodedHeader = base64UrlEncoder.encode(headerBytes);
        String base64UrlEncodedEncryptedKey = base64UrlEncoder.encode(encryptedCek);
        String base64UrlEncodedIv = base64UrlEncoder.encode(iv);
        String base64UrlEncodedCiphertext = base64UrlEncoder.encode(ciphertext);
        String base64UrlEncodedAad = base64UrlEncoder.encode(tag);

        return
            base64UrlEncodedHeader + JwtParser.SEPARATOR_CHAR +
            base64UrlEncodedEncryptedKey + JwtParser.SEPARATOR_CHAR +
            base64UrlEncodedIv + JwtParser.SEPARATOR_CHAR +
            base64UrlEncodedCiphertext + JwtParser.SEPARATOR_CHAR +
            base64UrlEncodedAad;
    }
}
