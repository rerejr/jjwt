package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.KeyRequest;

import java.security.Key;

public class DefaultKeyRequest<T extends Key> implements KeyRequest<T> {

    private final T key;

    public DefaultKeyRequest(T key) {
        this.key = Assert.notNull(key, "Key cannot be null.");
    }

    @Override
    public T getKey() {
        return this.key;
    }
}
