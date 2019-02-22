package edu.albany.securecmail3.shamirsecret;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.Random;

import com.google.gson.Gson;

public final class Shamir
{
    public static SecretShare[] split(final BigInteger secret, int needed, int available, BigInteger prime, Random random)
    {
        System.out.println("Prime Number: " + prime);

        final BigInteger[] coeff = new BigInteger[needed];
        coeff[0] = secret;
        for (int i = 1; i < needed; i++)
        {
            BigInteger r;
            while (true)
            {
                r = new BigInteger(prime.bitLength(), random);
                if (r.compareTo(BigInteger.ZERO) > 0 && r.compareTo(prime) < 0)
                {
                    break;
                }
            }
            coeff[i] = r;
        }

        final SecretShare[] shares = new SecretShare[available];
        for (int x = 1; x <= available; x++)
        {
            BigInteger accum = secret;

            for (int exp = 1; exp < needed; exp++)
            {
                accum = accum.add(coeff[exp].multiply(BigInteger.valueOf(x).pow(exp).mod(prime))).mod(prime);
            }
            shares[x - 1] = new SecretShare(x, accum);
            System.out.println("Share " + shares[x - 1]);
        }

        return shares;
    }

    public static BigInteger combine(final SecretShare[] shares, final BigInteger prime)
    {
        BigInteger accum = BigInteger.ZERO;

        for(int formula = 0; formula < shares.length; formula++)
        {
            BigInteger numerator = BigInteger.ONE;
            BigInteger denominator = BigInteger.ONE;

            for(int count = 0; count < shares.length; count++)
            {
                if(formula == count)
                    continue; // If not the same value

                int startposition = shares[formula].getNumber();
                int nextposition = shares[count].getNumber();

                numerator = numerator.multiply(BigInteger.valueOf(nextposition).negate()).mod(prime); // (numerator * -nextposition) % prime;
                denominator = denominator.multiply(BigInteger.valueOf(startposition - nextposition)).mod(prime); // (denominator * (startposition - nextposition)) % prime;
            }
            BigInteger value = shares[formula].getShare();
            BigInteger tmp = value.multiply(numerator) . multiply(modInverse(denominator, prime));
            accum = prime.add(accum).add(tmp) . mod(prime); //  (prime + accum + (value * numerator * modInverse(denominator))) % prime;
        }

        System.out.println("The secret is: " + accum + "\n");

        return accum;
    }

    private static BigInteger[] gcdD(BigInteger a, BigInteger b)
    {
        if (b.compareTo(BigInteger.ZERO) == 0)
            return new BigInteger[] {a, BigInteger.ONE, BigInteger.ZERO};
        else
        {
            BigInteger n = a.divide(b);
            BigInteger c = a.mod(b);
            BigInteger[] r = gcdD(b, c);
            return new BigInteger[] {r[0], r[2], r[1].subtract(r[2].multiply(n))};
        }
    }

    private static BigInteger modInverse(BigInteger k, BigInteger prime)
    {
        k = k.mod(prime);
        BigInteger r = (k.compareTo(BigInteger.ZERO) == -1) ? (gcdD(prime, k.negate())[2]).negate() : gcdD(prime,k)[2];
        return prime.add(r).mod(prime);
    }

    public static void main(final String[] args) throws IOException, ClassNotFoundException
    {
    	/*
    	SecureRandom sr = new SecureRandom();
    	Test test = new Test();
    	Scheme scheme = new Scheme(sr, 2, 2);
    	test.setTest("hello there");
    	test.setTest2(new File("test"));
        byte[] secret = serialize(test);
        Map<Integer, byte[]> parts = scheme.split(secret);
        byte[] bytes = serialize(parts);
        String string = Base64.getEncoder().encodeToString(bytes);
        int mid;
        if(string.length() %2 == 0) {
            mid = string.length() / 2; //get the middle of the String
        }
        else
        {
            mid = (string.length() / 2) + 1;
        }
        
        
        String[] bodyparts = {string.substring(0, mid), string.substring(mid)};
        Gson gson = new Gson();
        String gs = gson.toJson(bodyparts);
        
        
        Gson gson1 = new Gson();
        String[] bodypartss = gson1.fromJson(gs, String[].class);
        String co = bodypartss[0].concat(bodypartss[1]);
        byte[] b = Base64.getDecoder().decode(co);
        Map<Integer, byte[]> parts2 = (Map<Integer, byte[]>) deserialize(b);
        SecureRandom sr1 = new SecureRandom();
        Scheme scheme2 = new Scheme(sr1,2,2);
        byte[] recovered = scheme2.join(parts2);
        Test test2 = (Test) deserialize(recovered);
        System.out.println(test.getTest());
        System.out.println(test2.getTest2());
    	
    	*/
        final int CERTAINTY = 256;
        final SecureRandom random = new SecureRandom();
        String str = "This is the text";
        byte[] arr = str.getBytes();
        
        final BigInteger secret = new BigInteger("123");
        
        // prime number must be longer then secret number
        final BigInteger prime = new BigInteger(secret.bitLength() + 1, CERTAINTY, random);

        // 2 - at least 2 secret parts are needed to view secret
        // 5 - there are 5 persons that get secret parts
        final SecretShare[] shares = Shamir.split(secret, 2, 2, prime, random);


        // we can use any combination of 2 or more parts of secret
        SecretShare[] sharesToViewSecret = new SecretShare[] {shares[0],shares[1]}; // 0 & 1
        BigInteger result = combine(sharesToViewSecret, prime);


        System.out.println("Result is :" + result);
        
    }

	private static Object deserialize(byte[] bytes) throws IOException, ClassNotFoundException {
		Key.xor = 0x7555AAAA; // make the hashcodes different
        ObjectInputStream objIn = new ObjectInputStream(new ByteArrayInputStream(bytes));
        Object actual = objIn.readObject();
		return actual;
	}
	

    public static byte[] serialize(Object obj) throws IOException {
        try (ByteArrayOutputStream b = new ByteArrayOutputStream()) {
            try (ObjectOutputStream o = new ObjectOutputStream(b)) {
                o.writeObject(obj);
            }
            return b.toByteArray();
            

        }
    }

}