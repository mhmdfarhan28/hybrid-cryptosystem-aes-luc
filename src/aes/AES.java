package aes;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;

public class AES {
    private int[][] w;
    private int[][] state;
    private int Nk, Nb, Nr;

    private final int[] sBox = new int[]{
        //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,  // 0
                0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,  // 1
                0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,  // 2
                0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,  // 3
                0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,  // 4
                0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,  // 5
                0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,  // 6
                0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,  // 7
                0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,  // 8
                0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,  // 9
                0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,  // A
                0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,  // B
                0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,  // C
                0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,  // D
                0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,  // E
                0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}; // F

    private final int[] invsBox = new int[] {
        //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,  // 0
                0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,  // 1
                0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,  // 2
                0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,  // 3
                0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,  // 4
                0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,  // 5
                0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,  // 6
                0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,  // 7
                0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,  // 8
                0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,  // 9
                0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,  // A
                0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,  // B
                0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,  // C
                0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,  // D
                0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,  // E
                0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d }; // F

    private final int[][] rCon = new int[][]{{
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36}, {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};

    //-----------------
    // 00 01 02 03 ----
    // 10 11 12 13 ----
    // 20 21 22 23 ----
    // 30 31 32 33 ----
    //-----------------

    public AES(int size) {
        if(size == 128){
            Nk = 4;
            Nb = 4;
            Nr = 10;
        }
        else if(size == 192){
            Nk = 6;
            Nb = 4;
            Nr = 12;
        }
        else {
            Nk = 8;
            Nb = 4;
            Nr = 14;
        }
        state = new int[Nr+1][16];
    }
    public int getNr(){
        return Nr;
    }

    public void addRoundKey(int[][] state, int round){//-----------------
        // 00 01 02 03 ----
        // 10 11 12 13 ----
        // 20 21 22 23 ----
        // 30 31 32 33 ----
        //-----------------
        for (int c = 0; c < Nb; c++) {
            for (int r = 0; r < 4; r++) {
                state[r][c] = state[r][c] ^ ((w[r][(round*4)+c]));
            }
        }
    }

    public void subBytes(int[][] state){
        for (int c = 0; c < Nb; c++) {
            for (int r = 0; r < 4; r++) {
                state[r][c] = sBox[state[r][c]];
            }
        }
    }

    public void shiftRows(int[][] state){
        int r,c;
        int[][] temp = new int[4][4];
        for(r = 1 ; r < 4; r++){
            for (c = 0; c < 4; c++){
                temp[r][c] = state[r][c];
            }
        }
        for(r = 1 ; r < 4; r++){
            for (c = 0; c < 4; c++) {
                /*10 = 11
                11 = 12
                12 = 13
                13 = 10

                20 = 22
                21 = 23
                22 = 20
                23 = 21

                30 = 33
                31 = 30
                32 = 31
                33 = 32*/
                state[r][c] = temp[r][(r+c)%4];

            }
        }

    }

    public void mixColumn(int[][] state){
        int temp0, temp1, temp2, temp3;
        for (int c = 0; c < Nb; c++) {

            temp0 = mult(2, state[0][c]) ^ mult(3, state[1][c]) ^ state[2][c] ^ state[3][c];
            temp1 = state[0][c] ^ mult(2, state[1][c]) ^ mult(3, state[2][c]) ^ state[3][c];
            temp2 = state[0][c] ^ state[1][c] ^ mult(2, state[2][c]) ^ mult(3, state[3][c]);
            temp3 = mult(3, state[0][c]) ^ state[1][c] ^ state[2][c] ^ mult(2, state[3][c]);

            state[0][c] = temp0;
            state[1][c] = temp1;
            state[2][c] = temp2;
            state[3][c] = temp3;
        }
    }

    public void invShiftRows(int[][] state){
        int r,c;
        int[][] temp = new int[4][4];
        for(r = 1 ; r < 4; r++){
            for (c = 0; c < 4; c++){
                temp[r][c] = state[r][c];
            }
        }
        for(r = 1 ; r < 4; r++){
            for (c = 0; c < 4; c++) {
                // 00 01 02 03 ----
                // 10 11 12 13 ---- 13 10 11 12
                // 20 21 22 23 ---- 22 23 20 21
                // 30 31 32 33 ---- 31 32 33 30
                //-----------------
                state[r][c] = temp[r][(c + 4 - r)%4];

            }
        }
    }

    public void invSubBytes(int[][] state){
        for (int c = 0; c < Nb; c++) {
            for (int r = 0; r < 4; r++) {
                state[r][c] = invsBox[state[r][c]];
            }
        }
    }

    public void invMixColumn(int[][] state){
        int temp0, temp1, temp2, temp3;
        for (int c = 0; c < Nb; c++) {

            temp0 = mult(14, state[0][c]) ^ mult(11, state[1][c]) ^ mult(13, state[2][c]) ^ mult(9, state[3][c]);
            temp1 = mult(9, state[0][c]) ^ mult(14, state[1][c]) ^ mult(11, state[2][c]) ^ mult(13, state[3][c]);
            temp2 = mult(13, state[0][c]) ^ mult(9, state[1][c]) ^ mult(14, state[2][c]) ^ mult(11, state[3][c]);
            temp3 = mult(11, state[0][c]) ^ mult(13, state[1][c]) ^ mult(9, state[2][c]) ^ mult(14, state[3][c]);

            state[0][c] = temp0;
            state[1][c] = temp1;
            state[2][c] = temp2;
            state[3][c] = temp3;
        }
    }

    public void keySchedule(int[][] secretkey){
        //-----------------
        // 00 01 02 03 ---- 13
        // 10 11 12 13 ---- 23
        // 20 21 22 23 ---- 33
        // 30 31 32 33 ---- 03
        //-----------------
        w = new int[4][Nb*(Nr+1)];
        for (int c = 0;c < Nk; c++){
            for (int r = 0;r < 4; r++){
                w[r][c] = secretkey[r][c];
            }
        }

        for(int c = Nk; c < Nb*(Nr+1); c++){
            for (int r = 0;r < 4; r++){
                if(c % Nk == 0) {
                    //w[j][i] = w[j][i-4] ^ sBox[w[(j+1)%4][i-1]];
                    w[r][c] = w[r][c-Nk] ^ sBox[w[(r+1)%4][c-1]] ^ rCon[r][c/Nk];

                }
                else{
                    w[r][c] = w[r][c-Nk] ^ w[r][c-1];

                }
            }
        }
    }


    public String ecb_encrypt(String text, int[][] secretkey) throws UnsupportedEncodingException {
        String outputtext = "";
        //1 blok = 16 byte
        int blok = ((text.length() - 1) / 16 + 1);
        int[][][] intTeks = new int[blok][4][4];
        String temptext;
        for (int i = 1; i <= blok; i++) {
            if (i == blok) {
                temptext = text.substring(8 * (i - 1));
            } else {
                temptext = text.substring(8 * (i - 1), 8 * i);
            }
            int[][] textblok = getMatriks(temptext.getBytes("UTF-16BE"));
            int[][] cipherteks = encrypt(textblok, secretkey);
            intTeks[i-1] = cipherteks;
            outputtext += intToHexString(cipherteks);
        }
        return outputtext;
    }

    public String ecb_decrypt(String text, int[][] secretkey) throws UnsupportedEncodingException{
        String outputtext = "";
        String stringTeksASCII = "";
        int[][][] intText = stringToHex(text);
        int blok = intText.length;
        for (int i = 1; i <= blok; i++) {
            int[][] decyptedteks = decrypt(intText[i - 1], secretkey);
            stringTeksASCII += new String(reserveMatriks(decyptedteks), "UTF-16BE");
            outputtext = outputtext + "" + intToHexString(decyptedteks);
        }
        return stringTeksASCII;
    }

    public int[][] encrypt(int[][] state,int[][] secretkey){
        int round = 0;
        keySchedule(secretkey);
        addRoundKey(state,round);
        setStateRound(state, round);
        for (round = 1; round < Nr; round++){
            subBytes(state);
            shiftRows(state);
            mixColumn(state);
            addRoundKey(state, round);
            setStateRound(state, round);
        }
        subBytes(state);
        shiftRows(state);
        addRoundKey(state, round);
        setStateRound(state, round);
        return state;
    }

    public int[][] decrypt(int[][] state,int[][] secretkey){
        int round = Nr;
        keySchedule(secretkey);
        addRoundKey(state,round);
        for (round = Nr-1; round > 0; round--){
            invShiftRows(state);
            invSubBytes(state);
            addRoundKey(state, round);
            invMixColumn(state);
        }
        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, round);

        return state;
    }

    public static int[][][] stringToHex(String text){
        String[] array = text.split(" ");
        int blok = array.length/16;
        int[][][] intText = new int[blok][4][4];
        int l = 0;
        for (int i = 1; i <= blok; i++) {
            for (int j = 0; j < 4;j++){
                for (int k= 0; k < 4;k++){
                    intText[i-1][j][k] = Integer.parseInt(array[l],16);
                    l++;
                }
            }

        }
        return intText;
    }

    public String intToHexString(int[][] state){
        String out = "";
        for (int i = 0;i < 4; i++){
            for (int j = 0;j < 4; j++){
                out += Integer.toHexString(state[i][j])+" ";
            }
        }
        return out;
    }

    public String toHex(String text) throws UnsupportedEncodingException {
        String out = "";
        byte[] arraytext = text.getBytes("UTF-16BE");
        for (int i=0;i<arraytext.length;i++){
            out+= Integer.toHexString(arraytext[i] & 0xFF)+" ";
        }
        return out;
    }

    public int mult(int a, int b){
        int sum = 0;
        while (a != 0) { // while it is not 0
            if ((a & 1) != 0) { // check if the first bit is 1
                sum = sum ^ b; // add b from the smallest bit
            }
            // bit shift left mod 0x11b if necessary;
            if ((b & 0x80) == 0) {
                b <<= 1;
            }
            else{
                b = (b << 1) ^ 0x11b;
            }
            a = a >> 1; // lowest bit of "a" was used so shift right
        }
        return sum;
    }

    //State to arrayofByte
    public byte[] reserveMatriks(int[][] input){
        int k = 0;
        byte[] out = new byte[input.length * input[0].length];//length r * and length c
        for (int c = 0;c < input[0].length; c++){
            for (int r = 0;r < 4; r++){
                out[k] = (byte) input[r][c];
                k++;
            }
        }
        return out;
    }

    public int[][] getMatriksKey(byte[] input){
        int k = 0;
        int[][] out = new int[4][input.length/4];
        for (int c = 0;c < input.length/4; c++){
            for (int r = 0;r < 4; r++){
                out[r][c] = input[k] & 0xFF;
                k++;
            }
        }
        return out;
    }

    // getState (4x4) Matriks
    public int[][] getMatriks(byte[] input){
        int k = 0;
        int[][] out = new int[4][4];
        for (int c = 0;c < 4; c++){
            for (int r = 0;r < 4; r++){
                if(k >= input.length){ //padding with null
                    out[r][c]=00;
                }
                else{
                    out[r][c] = input[k] & 0xFF;
                }
                k++;
            }
        }
        return out;
    }

    public void setStateRound(int[][] state, int round){
        int k=0;
        for (int i = 0;i < 4; i++){
            for (int j = 0;j < 4; j++){
                this.state[round][k] = state[i][j];
                k++;
            }
        }
    }

    public int[][] getStateRound(){
        return this.state;
    }

    public int getBitDif(int[] text1,int[] text2){
        int bit,xor,a,b;
        int sum = 0;
        for (int i = 0;i < 16; i++){
            a = text1[i];
            b = text2[i];
            xor = a ^ b;
            bit =  countBinary(xor);
            sum += bit;
            //System.out.println(a +" XOR "+ b +"= "+ xor + " / Perubahan Bit = "+bit);
        }
        return sum;
    }

    public String avalanche(String text1,String text2){
        String[] arraytext1 = text1.split(" ");
        String[] arraytext2 = text2.split(" ");
        int bit,xor,a,b;
        int sum = 0;
        for (int i = 0;i < arraytext1.length; i++){
            a = Integer.parseInt(arraytext1[i],16);
            b = Integer.parseInt(arraytext2[i],16);
            xor = a ^ b;
            bit =  countBinary(xor);
            sum += bit;
            //System.out.println(a +" XOR "+ b +"= "+ xor + " / Perubahan Bit = "+bit);
        }
        //System.out.println("Jumlah bit = "+sum);
        float aevalue = (float)sum/(arraytext1.length*8)*100;
        //System.out.println("Avalanche Effect = "+aevalue+" %");
        return aevalue+" %";
    }

    public int countBinary(int n){
        int count = 0;
        while (n > 0){
            count = count + 1;
            n = n & (n-1);
        }
        return count;
    }

}
