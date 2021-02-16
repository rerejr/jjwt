package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.KeyResult;

import javax.crypto.SecretKey;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

public class DefaultKeyResult implements KeyResult {

    private final SecretKey key;
    private final byte[] encryptedKey;
    private final Map<String, ?> headerParams;

    public DefaultKeyResult(SecretKey key) {
        this(key, new byte[0]);
    }

    public DefaultKeyResult(SecretKey key, byte[] encryptedKey) {
        this(key, encryptedKey, Collections.<String, Object>emptyMap());
    }

    public DefaultKeyResult(SecretKey key, byte[] encryptedKey, Map<String, ?> headerParams) {
        this.encryptedKey = Assert.notNull(encryptedKey, "encryptedKey cannot be null (but can be empty).");
        this.key = Assert.notNull(key, "Key argument cannot be null.");
        Assert.notNull(headerParams, "headerParams cannot be null.");
        this.headerParams = Collections.unmodifiableMap(new LinkedHashMap<>(headerParams));
    }

    @Override
    public SecretKey getKey() {
        return this.key;
    }

    @Override
    public byte[] getEncryptedKey() {
        return this.encryptedKey;
    }

    @Override
    public Map<String, ?> getHeaderParams() {
        return this.headerParams;
    }
}
