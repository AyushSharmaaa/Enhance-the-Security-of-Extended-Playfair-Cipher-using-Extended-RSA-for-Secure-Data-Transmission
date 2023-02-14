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
        String pt = plaintext;
        int charsperchunk = (N.bitLength()-1)/8;
        while (plaintext.length() % charsperchunk != 0)
            plaintext += ' ';
        int chunks = plaintext.length()/ charsperchunk;
        BigInteger[] c = new BigInteger[chunks];
        for (int i = 0; i < chunks; i++) {
            String s = plaintext.substring(charsperchunk*i,charsperchunk*(i+1));
            c[i] = string2int(pt);
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



            /**System.out.println("Encoded Text, computed with RSA:");
            BigInteger[] cyphertext = encode(s,N,e);
            for (int i = 0; i < cyphertext.length; i++) {
                System.out.println("     " + cyphertext[i]);
            }

            System.out.println();

            System.out.println("Decoded Text, computed with RSA:");
            String plaintext = decode(cyphertext,N,d);
            System.out.println("     " + plaintext);*/

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
