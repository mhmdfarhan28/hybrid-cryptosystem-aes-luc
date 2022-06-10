package luc;

import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import aes.AES;
import java.util.Random;

public class Main {
    public static void main(String[] args) throws UnsupportedEncodingException {
        LUC luc = new LUC(12);
        luc.setPublicKey();
        byte[] x = {127};
        String a ="ᣛ⦱\u1CAC١ܬ⪝\u0C84߸";
        //String a ="ABCDEFGH";
        byte[] y = a.getBytes("UTF-16BE");
        System.out.println(y.length);
        BigInteger w = BigInteger.ZERO;
        for (int i =0;i<y.length;i+=2){
            //System.out.println((y[i]&0xFF)+" "+(y[i+1]&0xFF));
            w = w.add(BigInteger.valueOf(4).pow(i*2).multiply(BigInteger.valueOf(y[y.length-i-1]&0xFF)));
        }
        System.out.println(w);
        BigInteger b = new BigInteger("32833");
        byte g = (byte) (b.divide(BigInteger.valueOf(256)).byteValue()&0xFF);
        byte[] c = {00,65,00,66,80,41};
        System.out.println(new String(c, "UTF-16BE"));



        BigInteger[] cipherkey = luc.enc(y, luc.getE(), luc.getN());
        System.out.println("Cipher key = " + luc.bigIntToString(cipherkey));
        System.out.println("Cipher text = "+ luc.dec(cipherkey,luc.getE(), luc.getN(),luc.getP(), luc.getQ()));

        /*Random r = new Random();
        BigInteger p = BigInteger.probablePrime(8, r);
        BigInteger q;
        for (int i=0;i<4096;i++) {
            do {
                q = BigInteger.probablePrime(8, r);
            } while (q.compareTo(p)==0);
            System.out.println(p + " " + q);
        }*/
        /*long startTime = System.nanoTime();
        LUC luc = new LUC();
        String a = "ABCDEFGHIJKLMNO";
        byte[] x = a.getBytes(StandardCharsets.UTF_8);
        System.out.println(new BigInteger(x));
        BigInteger[] b = luc.convertInt(x);
        String c = new String(x, StandardCharsets.UTF_8);
        System.out.println(c);
        String outb = new String(b[0].toByteArray(), StandardCharsets.UTF_8);
        System.out.println(outb);

        BigInteger[] key = luc.setPublicKey();
        BigInteger[] cipherkey = luc.enc(x, key[0], key[1]);
        System.out.println("Cipher key = " + luc.arrayBigInteger(cipherkey));
        //byte[] f = luc.decryptLUC(cipherkey).toByteArray();
        String f = luc.dec(cipherkey, key[0], key[1], key[2], key[3]);
        System.out.println("Decrypted cipher key = " + f);

        long endTime   = System.nanoTime();
        long totalTime = endTime - startTime;
        System.out.println(totalTime+ " nanosecond");*/


    }
}
