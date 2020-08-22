package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.Named;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.CryptoRequest;

import java.security.SecureRandom;

abstract class CryptoAlgorithm implements Named {

    private final String name;

    private final String jcaName;

    CryptoAlgorithm(String name, String jcaName) {
        Assert.hasText(name, "name cannot be null or empty.");
        this.name = name;
        Assert.hasText(jcaName, "jcaName cannot be null or empty.");
        this.jcaName = jcaName;
    }

    @Override
    public String getName() {
        return this.name;
    }

    String getJcaName() {
        return this.jcaName;
    }

    SecureRandom ensureSecureRandom(CryptoRequest<?,?> request) {
        SecureRandom random = request.getSecureRandom();
        return random != null ? random : Randoms.secureRandom();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof CryptoAlgorithm) {
            CryptoAlgorithm other = (CryptoAlgorithm)obj;
            return this.name.equals(other.getName()) && this.jcaName.equals(other.getJcaName());
        }
        return false;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 31 * hash + name.hashCode();
        hash = 31 * hash + jcaName.hashCode();
        return hash;
    }

    @Override
    public String toString() {
        return name;
    }
}
