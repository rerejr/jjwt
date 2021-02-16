package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.security.KeyAlgorithm;
import io.jsonwebtoken.security.KeyRequest;
import io.jsonwebtoken.security.KeyResult;

import javax.crypto.SecretKey;

public class DirectKeyAlgorithm implements KeyAlgorithm<SecretKey, KeyRequest<SecretKey>> {

    static final String NAME = "dir";

    @Override
    public KeyResult getKey(KeyRequest<SecretKey> request) {
        return new DefaultKeyResult(request.getKey());
    }

    @Override
    public String getName() {
        return NAME;
    }
}
