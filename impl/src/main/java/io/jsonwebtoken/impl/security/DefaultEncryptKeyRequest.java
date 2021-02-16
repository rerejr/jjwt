package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;

import javax.crypto.SecretKey;
import java.security.Key;
import java.security.Provider;
import java.security.SecureRandom;

public class DefaultEncryptKeyRequest<T extends Key> extends DefaultKeyRequest<T> implements EncryptKeyRequest<T> {

    private final Provider provider;
    private final SecureRandom secureRandom;
    private final SecretKey contentEncryptionKey;

    public DefaultEncryptKeyRequest(T key, SecretKey contentEncryptionKey, Provider provider, SecureRandom secureRandom) {
        super(key);
        this.contentEncryptionKey = Assert.notNull(contentEncryptionKey, "contentEncryptionKey cannot be null.");
        this.provider = provider;
        this.secureRandom = secureRandom;
    }

    @Override
    public Provider getProvider() {
        return this.provider;
    }

    @Override
    public SecureRandom getSecureRandom() {
        return this.secureRandom;
    }

    @Override
    public SecretKey getData() {
        return this.contentEncryptionKey;
    }
}
