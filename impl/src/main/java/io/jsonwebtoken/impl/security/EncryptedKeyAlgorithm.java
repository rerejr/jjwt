package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.security.KeyAlgorithm;

import java.security.Key;

public interface EncryptedKeyAlgorithm<K extends Key, R extends EncryptKeyRequest<K>> extends KeyAlgorithm<K, R> {

}
