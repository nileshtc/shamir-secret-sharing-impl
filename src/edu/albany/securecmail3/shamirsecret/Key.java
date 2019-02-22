package edu.albany.securecmail3.shamirsecret;

import java.io.Serializable;

public class Key implements Serializable
{
    private String  keyString;
    static int xor = 0;

    Key(String keyString)
    {
        this.keyString = keyString;
    }

    @Override
    public int hashCode()
    {
        return keyString.hashCode()^xor;
    }

    @Override
    public boolean equals(Object obj)
    {
        Key otherKey = (Key) obj;
        return keyString.equals(otherKey.keyString);
    }
}
