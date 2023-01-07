package cryptography_practical;

import java.math.BigInteger;
import java.util.Random;
import java.io.*;
import java.util.Scanner;

public class RSA {

    static int bits = 128;


    /**
     *  Convert a string into a BigInteger.  The string should consist of
     *  ASCII characters only.  The ASCII codes are simply concatenated to
     *  give the integer.
     */
    public static BigInteger string2int(String str) {
        byte[] b = new byte[str.length()];
        for (int i = 0; i < b.length; i++)
            b[i] = (byte)str.charAt(i);
        return new BigInteger(1,b);
    }


    /**
     *  Convert a BigInteger into a string of ASCII characters.  Each byte
     *  in the integer is simply converted into the corresponding ASCII code.
     */
    public static String int2string(BigInteger n) {
        byte[] b = n.toByteArray();
        StringBuffer s = new StringBuffer();
        for (int i = 0; i < b.length; i++)
            s.append((char)b[i]);
        return s.toString();
    }


    /**
     *  Apply RSA encryption to a string, using the key (N,e).  The string
     *  is broken into chunks, and each chunk is converted into an integer.
     *  Then that integer, x, is encoded by computing  x^e (mod N).
     */
    public static BigInteger[] encode(String plaintext, BigInteger N, BigInteger e) {
        int charsperchunk = (N.bitLength()-1)/8;
        while (plaintext.length() % charsperchunk != 0)
            plaintext += ' ';
        int chunks = plaintext.length()/ charsperchunk;
        BigInteger[] c = new BigInteger[chunks];
        for (int i = 0; i < chunks; i++) {
            String s = plaintext.substring(charsperchunk*i,charsperchunk*(i+1));
            c[i] = string2int(s);
            c[i] = c[i].modPow(e,N);
        }
        return c;
    }


    /**
     *  Apply RSA decryption to a string, using the key (N,d).  Each integer x in
     *  the array of integers is first decoded by computing  x^d (mod N).  Then
     *  each decoded integers is converted into a string, and the strings are
     *  concatenated into a single string.
     */
    public static String decode(BigInteger[] cyphertext, BigInteger N, BigInteger d) {
        String s = "";
        for (int i = 0; i < cyphertext.length; i++)
            s += int2string(cyphertext[i].modPow(d,N));
        return s;
    }

    public static void main(String[] str) throws java.io.IOException {

        Random random = new Random();
        System.out.println("\n\nComputing public key (N,e) and private key (N,d):");

        // Choose two large primes p and q, let N  = pq, and let p1p1 = (p-1)(q-1).

        System.out.print("Computing p 1 ... ");
        System.out.flush();
        BigInteger p1 = new BigInteger(bits, 50, random);
        System.out.println(p1);
        System.out.print("Computing p 2... ");
        System.out.flush();
        BigInteger p2 = new BigInteger(bits, 50, random);
        System.out.println(p2);
        System.out.print("Computing q 1 ... ");
        System.out.flush();
        BigInteger q1 = new BigInteger(bits, 50, random);
        System.out.println(q1);
        System.out.print("Computing q 2 ... ");
        System.out.flush();
        BigInteger q2 = new BigInteger(bits, 50, random);
        System.out.println(q2);
        BigInteger N = p1.multiply(p2.multiply(q1.multiply(q2)));
        System.out.println("N = p1*p2*q1*q2 is       " + N);
        BigInteger p1phi = p1.subtract(BigInteger.ONE);
        BigInteger p2phi = p2.subtract(BigInteger.ONE);
        BigInteger q1phi = q1.subtract(BigInteger.ONE);
        BigInteger q2phi = q2.subtract(BigInteger.ONE);
        BigInteger phi_N = p1phi.multiply(p2phi.multiply(q1phi.multiply(q2phi)));
        System.out.println("phi(N) = (p1-1)(p2-1)(q1-1)(q2-1) is   " + phi_N);
        System.out.println();

        // Choose numbers e and d such that e is prime and ed = 1 mod N.

        BigInteger e = new BigInteger("" + 0x10001);
        System.out.println("Using e =       " + e);
        System.out.print("Computing d ... ");
        BigInteger d = e.modInverse(phi_N);
        System.out.println(d);

        // Now, the public key is the pair (N,d) and the private key
        // is the pair (N,e).  Do some encryptions and decryptions.
        // The user enters text that is encoded into an array of
        // integers.  (Use an array, not a single integer, since
        // the algorithm can only deals with a certain number of
        // characters at a time.)  Then this array is decoded to
        // give (if the algorithm is working) the original text.
        Scanner scanner = new Scanner(System.in);

            System.out.println("\n\nEnter plaintext, press return to end: ");
            System.out.print("     ");
            StringBuffer b = new StringBuffer(scanner.nextLine());

//            while (true) {
//                int ch = System.in.read();
//                if (ch == '\n' || ch == -1)
//                    break;
//                b.append((char)ch);
//            }
            String s = b.toString();
            if (s.trim().length() == 0) {
                System.out.println("length 0");
            }

            System.out.println();
            System.out.println("Encoded Text, computed with RSA:");
            BigInteger[] cyphertext = encode(s,N,e);
            for (int i = 0; i < cyphertext.length; i++) {
                System.out.println("     " + cyphertext[i]);
            }

            System.out.println();

            System.out.println("Decoded Text, computed with RSA:");
            String plaintext = decode(cyphertext,N,d);
            System.out.println("     " + plaintext);

    }

}


/**

Sample output:



Computing public key (N,e) and private key (N,d):
Computing p ... 319200099727882485429806856538202736871
Computing q ... 246159064610520038049244855155541352371
N = pq is       78573997972600264346584460847100321977431094318333378495095985823688804971141
(p-1)(q-1) is   78573997972600264346584460847100321976865735153994975971616934111995060881900

Using e =       65537
Computing d ... 27360684921993845196658436928630795548072889237366973566813709101268585446173


Enter plaintext, press return to end:
     Hobart and William Smith Colleges

Encoded Text, computed with RSA:
     54024531828062641058031068563440172837550642238555662849519589433244899279164
     53429835691845923964879155722416168978469031140770148390200920077312135574494

Decoded Text, computed with RSA:
     Hobart and William Smith Colleges
*/