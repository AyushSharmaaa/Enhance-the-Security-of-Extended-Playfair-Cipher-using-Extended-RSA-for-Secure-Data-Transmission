package cryptography_practical;

import java.awt.Point;
import java.util.Scanner;
public class PlayfairCipher extends RSA
{
    //length of digraph array
    private int length = 0;

    //creates a matrix for Playfair cipher
    private String [][] table;

    //constructor of the class
    private PlayfairCipher()
    {
        Scanner sc = new Scanner(System.in);
        //prompts user for message to be encoded
        System.out.print("Enter the plaintext to be encipher: ");
        String input = parseString(sc);
        while(input.equals("")) {
            input = parseString(sc);
        }
        //prompts user for the keyword to use for encoding & creates tables
        System.out.print("Enter the key for playfair cipher: ");
        String key = removeDuplicatesInKey(sc);
        while(key.equals("")) {
            key = removeDuplicatesInKey(sc);
        }
        table = this.cipherTable(key);
        //encodes and then decodes the encoded message
        String output = cipher(input);
        String decodedOutput = decode(output);
        //output the results to user
        this.keyTable(table);
        this.printResults(output,decodedOutput);
    }

    private static String removeDuplicatesInKey(Scanner scanner)
    {
        String s = scanner.nextLine();
        String str = new String();
        int len = s.length();

        // loop to traverse the string and
        // check for repeating chars using
        // IndexOf() method in Java
        for (int i = 0; i < len; i++)
        {
            // character at i'th index of s
            char c = s.charAt(i);

            // if c is present in str, it returns
            // the index of c, else it returns -1
            if (str.indexOf(c) < 0)
            {
                // adding c to str if -1 is returned
                str += c;
            }
        }
        return str;
    }

    //parses an input string to remove numbers, punctuation,

    private String parseString(Scanner sc)
    {
        String parse = sc.nextLine();
        //ascii value of space 32
//        int a=32;
//        char c=(char)a;
        // parse = parse.replaceAll("\s", "");
        return parse;
    }

    //creates the cipher table based on some input string (already parsed)
    private String[][] cipherTable(String key)
    {
        //creates a matrix of 16*16
        String[][] playfairTable = new String[16][16];
        //1-256 all char
        String str="";
        for (int i=0; i<=255; i++) {
            char c = (char) i;
            str = str+c;
        }
        String keyString = key + str;
        //fill string array with empty string
        for(int i = 0; i < 16; i++)
            for(int j = 0; j < 16; j++)
                playfairTable[i][j] = "";
        for(int k = 0; k < keyString.length(); k++)
        {
            boolean repeat = false;
            boolean used = false;
            for(int i = 0; i < 16; i++)
            {
                for(int j = 0; j < 16; j++)
                {
                    if(playfairTable[i][j].equals("" + keyString.charAt(k)))
                    {
                        repeat = true;
                    }
                    else if(playfairTable[i][j].equals("") && !repeat && !used)
                    {
                        playfairTable[i][j] = "" + keyString.charAt(k);
                        used = true;
                    }
                }
            }
        }
        return playfairTable;
    }

    //cipher: takes input (all upper-case), encodes it, and returns the output
    private String cipher(String in)
    {
        // null value to be inserted at even length or repeated char pair
        char nullVal = (char)0;
        length = (int) in.length() / 2 + in.length() % 2;
        //insert x between double-letter digraphs & redefines "length"

        for(int i = 0; i < (length - 1); i++)
        {
            if(in.charAt(2 * i) == in.charAt(2 * i + 1))
            {
                in = new StringBuffer(in).insert(2 * i + 1, nullVal).toString();
                length = (int) in.length() / 2 + in.length() % 2;
            }
        }
//------------makes plaintext of even length--------------
// creates an array of digraphs
        String[] digraph = new String[length];
        //loop iterates over the plaintext
        for(int j = 0; j < length ; j++)
        {
            //checks the plaintext is of even length or not
            if(j == (length - 1) && in.length() / 2 == (length - 1))
                //if not addends X at the end of the plaintext
                in = in + nullVal;
            digraph[j] = in.charAt(2 * j) +""+ in.charAt(2 * j + 1);
        }
        //encodes the digraphs and returns the output
        String out = "";
        String[] encDigraphs = new String[length];
        encDigraphs = encodeDigraph(digraph);
        for(int k = 0; k < length; k++)
            out = out + encDigraphs[k];
        return out;
    }

    //---------------encryption logic-----------------
    //encodes the digraph input with the cipher's specifications
    private String[] encodeDigraph(String di[])
    {
        String[] encipher = new String[length];
        for(int i = 0; i < length; i++)
        {
            char a = di[i].charAt(0);
            char b = di[i].charAt(1);
            int r1 = (int) getPoint(a).getX();
            int r2 = (int) getPoint(b).getX();
            int c1 = (int) getPoint(a).getY();
            int c2 = (int) getPoint(b).getY();
            //executes if the letters of digraph appear in the same row
            // in such case shift columns to right
            if(r1 == r2)
            {
                c1 = (c1 + 1) % 16;
                c2 = (c2 + 1) % 16;
            }
            //executes if the letters of digraph appear in the same column
           //in such case shift rows down
            else if(c1 == c2)
            {
                r1 = (r1 + 1) % 16;
                r2 = (r2 + 1) % 16;
            }
             //executes if the letters of digraph appear in the different row and different column
            //in such case swap the first column with the second column
            else
            {
                int temp = c1;
                c1 = c2;
                c2 = temp;
            }
            //performs the table look-up and puts those values into the encoded array
            encipher[i] = table[r1][c1] + "" + table[r2][c2];
        }
        return encipher;
    }


    //-----------------------decryption logic---------------------

    // decodes the output given from the cipher and decode methods (opp. of encoding process)
    private String decode(String out)
    {
        String decoded = "";
        for(int i = 0; i < out.length() / 2; i++)
        {
            char a = out.charAt(2*i);
            char b = out.charAt(2*i+1);
            int r1 = (int) getPoint(a).getX();
            int r2 = (int) getPoint(b).getX();
            int c1 = (int) getPoint(a).getY();
            int c2 = (int) getPoint(b).getY();
            if(r1 == r2)
            {
                c1 = (c1 + 15) % 16;
                c2 = (c2 + 15) % 16;
            }
            else if(c1 == c2)
            {
                r1 = (r1 + 15) % 16;
                r2 = (r2 + 15) % 16;
            }
            else
            {
                //swapping logic
                int temp = c1;
                c1 = c2;
                c2 = temp;
            }
            decoded = decoded + table[r1][c1] + table[r2][c2];
        }

        //returns the decoded message
        return decoded;
    }

    // returns a point containing the row and column of the letter
    private Point getPoint(char c)
    {
        Point pt = new Point(0,0);
        for(int i = 0; i < 16; i++)
            for(int j = 0; j < 16; j++)
                if(c == table[i][j].charAt(0))
                    pt = new Point(i,j);
        return pt;
    }

    //function prints the key-table in matrix form for playfair cipher
    private void keyTable(String[][] printTable)
    {
        System.out.println("Playfair Cipher Key Matrix: ");
        System.out.println();
        //loop iterates for rows
        for(int i = 0; i < 16; i++)
        {
            //loop iterates for column
            for(int j = 0; j < 16; j++)
            {
                //prints the key-table in matrix form
                System.out.print(printTable[i][j]+" ");
            }
            System.out.println();
        }
        System.out.println();
    }

    //method that prints all the results
    private void printResults(String encipher, String dec)
    {
        System.out.print("Encrypted Message: ");
        //prints the encrypted message
        System.out.println(encipher);
        System.out.println();
        System.out.print("Decrypted Message: ");
        //prints the decryted message
        System.out.println(dec);
    }
    //main() method to test Playfair method

    public static void main(String args[])
    {
        PlayfairCipher pf = new PlayfairCipher();
    }
}
