package aes;

import java.awt.font.FontRenderContext;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

public class Main {
    public static void main(String[] args) throws UnsupportedEncodingException {
        String teks = "AAAAAAAA";
        String key1 = "12345678";
        String key2 = "12345678";
        AES aes = new AES(128);
        String c1 = aes.ecb_encrypt(teks,aes.getMatriksKey(key1.getBytes("UTF-16BE")));
        String c2 = aes.ecb_encrypt(teks,aes.getMatriksKey(key2.getBytes("UTF-16BE")));
        System.out.println(c1);
        System.out.println(c2);
        System.out.println(aes.avalanche(c1,c2));


    }




















    /*public static byte[] reserveMatriks(int[][] input){
        int k = 0;
        byte[] out = new byte[16];
        for (int c = 0;c < 4; c++){
            for (int r = 0;r < 4; r++){
                out[k] = (byte) input[r][c];
                k++;
            }
        }
        return out;
    }

    public static int[][] getMatriksKey(byte[] input){
        int k = 0;
        int[][] out = new int[4][input.length/4];
        for (int c = 0;c < input.length/4; c++){
            for (int r = 0;r < 4; r++){
                out[r][c] = input[k];
                System.out.print(out[r][c]+" ");
                k++;
            }
            System.out.println();
        }
        return out;
    }

    public static int[][] getMatriks(byte[] input){
        int k = 0;
        int[][] out = new int[4][4];
        for (int c = 0;c < 4; c++){
            for (int r = 0;r < 4; r++){
                if(k >= input.length){ //padding with null
                    out[r][c]=00;
                }
                else{
                    out[r][c] = input[k];
                }
                k++;
            }
        }
        return out;
    }*/
}
