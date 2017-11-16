import java.io.*;
import java.util.HashSet;
import java.util.Set;

public class MyFealLinear {

    static int text_count = 200;
    static String plaintext[] = new String[text_count];
    static String cyphertext[] = new String[text_count];
    static Set<Integer> candidateKeys = new HashSet<Integer>();

    private static int getBit(int num, int n) {
        return (num >> n) & 1;
    }

    private static int getBit2(int num, int n) {
        n = 31-n;
        return (num >> n) & 1;
    }

    private static int getLeft(String word_64) {
        return (int) Long.parseLong(word_64.substring(0,8), 16);
    }

    private static int getRigth(String word_64) {
        return (int) Long.parseLong(word_64.substring(8), 16);
    }

    private static String getBitString(int num) {
        String temp = "";

        for(int i=31; i>=0; i--)
            temp += getBit(num, i);

        return temp;
    }

    private static void readKnownTextPairs() {
        try {
            BufferedReader bufferedReader = new BufferedReader(new FileReader("known_mine.txt"));

            int count = 0;
            boolean isPlainText = true;

            String line = bufferedReader.readLine();

            while(line != null && count < plaintext.length) {
                if(line.length() != 0) {

                    if(isPlainText) {
                        plaintext[count] = line.substring(12);
                    }
                    else {
                        cyphertext[count] = line.substring(12);
                        count++;
                    }

                    isPlainText = !isPlainText;
                }

                line = bufferedReader.readLine();
            }

            bufferedReader.close();
        }
        catch(FileNotFoundException e) {
            System.out.println("Could not find file: known.txt");
        }
        catch(IOException e) {
            System.out.println("Unable to read file: IOException");
        }
    }

    private static int generate12BitKeyForInnerBytes(int k) {
        // K~ = (0, Kb1⊕Kb2, Kb3⊕Kb4, 0)
        // K~ = Keep 10-15, 18-23 and zero's for 24-32, 16-17.
        int a0 = (k >> 6) & 0x3F;
        int a1 = k & 0x3F;

        return (a0 << 16) + (a1 << 8) ;
    }

    static int calculateConstInnerBytes(int wordIndex, int key) {
        // Split pairs
        int L0 = getLeft(plaintext[wordIndex]);
        int R0 = getRigth(plaintext[wordIndex]);
        int L4 = getLeft(cyphertext[wordIndex]);
        int R4 = getRigth(cyphertext[wordIndex]);

        // S5,13,S21(L0⊕R0⊕L4)
        int a1 = getBit2(L0, 5)^getBit2(L0, 13)^getBit2(L0, 21)
                ^getBit2(R0, 5)^getBit2(R0, 13)^getBit2(R0, 21)
                ^getBit2(L4, 5)^getBit2(L4, 13)^getBit2(L4, 21);

        // S15(L0⊕L4⊕R4)
        int a2 = getBit2(L0, 15)^getBit2(L4, 15)^getBit2(R4, 15);

        // S15(F(L0⊕R0⊕K˜0))
        int a3 = getBit2(Integer.reverseBytes(FEALLinear.f(Integer.reverseBytes(L0^R0^key))), 15);

        // a = a1⊕a2⊕a3
        return a1 ^ a2 ^ a3;
    }

    private static int generate20BitKeyForOutterBytes(int k, int key_tilda) {
        int a0 = (key_tilda >> 16) & 0xFF;
        int a1 = (key_tilda >> 8) & 0xFF;

        int b0 = (k >> 12) & 0xFF;
        int b1 = 0;
        int b2 = 0;
        int b3 = (k >> 4) & 0xFF;

        int bits_2_3 = ((k & 0xF) >> 2) << 6;
        a0 = bits_2_3 + (a0);

        int bits_0_1 = (k & 0x3) << 6;
        a1 = bits_0_1 + a1;

        b1 = b0^a0;
        b2 = b3^a1;

        return (b0 << 24)  + (b1 << 16) + (b2 << 8) + b3;
    }

    static int calculateConstOutteBytes(int wordIndex, int key) {
        // Split pairs
        int L0 = getLeft(plaintext[wordIndex]);
        int R0 = getRigth(plaintext[wordIndex]);
        int L4 = getLeft(cyphertext[wordIndex]);
        int R4 = getRigth(cyphertext[wordIndex]);

        // a1 = S23,29(L0⊕R0⊕L4)
        int a1 = getBit2(L0, 13)^getBit2(R0, 13)^getBit2(L4, 13);

        // a2 = S31(L0⊕L4⊕R4)
        int a2 = getBit2(L0, 7)^getBit2(L0, 15)^getBit2(L0, 23)^getBit2(L0, 31)
                ^getBit2(L4, 7)^getBit2(L4, 15)^getBit2(L4, 23)^getBit2(L4, 31)
                ^getBit2(R4, 7)^getBit2(R4, 15)^getBit2(R4, 23)^getBit2(R4, 31);

        // a3 = S31(F(L0⊕R0⊕K0))
        int a3 = Integer.reverseBytes(FEALLinear.f(Integer.reverseBytes(L0^R0^key)));

        a3 = getBit2(a3, 7)^getBit2(a3, 15)^getBit2(a3, 23)^getBit2(a3, 31);

        // a = a1⊕a2⊕a3
        return a1^a2^a3;
    }

    static int calculateConstInnerBytesk1(int wordIndex, int key, int k0) {
        // Split pairs
        int L0 = getLeft(plaintext[wordIndex]);
        int R0 = getRigth(plaintext[wordIndex]);
        int L4 = getLeft(cyphertext[wordIndex]);
        int R4 = getRigth(cyphertext[wordIndex]);

        // S5,13,21(L0 ⊕ R4)
        int a1 = getBit2(L0, 5)^getBit2(R4, 5)^getBit2(L4, 5)
                ^getBit2(L0, 13)^getBit2(R4, 13)^getBit2(L4, 13)
                ^getBit2(L0, 21)^getBit2(R4, 21)^getBit2(L4, 21);

        // S15 F(L0 ⊕ F(L0 ⊕ R0 ⊕ K0) ⊕ K1)
        int y0 = Integer.reverseBytes(FEALLinear.f(Integer.reverseBytes(L0^R0^k0)));
        int a2 = getBit2(Integer.reverseBytes(FEALLinear.f(Integer.reverseBytes(L0^y0^key))), 15);

        // a = a1⊕a2
        return a1 ^ a2;
    }

    static int calculateConstOutteBytesk1(int wordIndex, int key, int k0) {
        // Split pairs
        int L0 = getLeft(plaintext[wordIndex]);
        int R0 = getRigth(plaintext[wordIndex]);
        int L4 = getLeft(cyphertext[wordIndex]);
        int R4 = getRigth(cyphertext[wordIndex]);

        // S13(L0 ⊕ R4)
        int a1 = getBit2(L0, 13)^getBit2(R4, 13)^getBit2(L4, 13);

        // S7,15,23,31 F(L0 ⊕ F(L0 ⊕ R0 ⊕ K0) ⊕ K1)
        int y0 = Integer.reverseBytes(FEALLinear.f(Integer.reverseBytes(L0^R0^k0)));
        int y1 = Integer.reverseBytes(FEALLinear.f(Integer.reverseBytes(L0^y0^key)));
        int a2 = getBit2(y1, 7)
                ^getBit2(y1, 15)
                ^getBit2(y1, 23)
                ^getBit2(y1, 31);

        // a = a1⊕a2
        return a1^a2;
    }

    static int calculateConstInnerBytesk2(int wordIndex, int key, int k0, int k1) {
        // Split pairs
        int L0 = getLeft(plaintext[wordIndex]);
        int R0 = getRigth(plaintext[wordIndex]);
        int L4 = getLeft(cyphertext[wordIndex]);
        int R4 = getRigth(cyphertext[wordIndex]);

        // S5,13,21(L0 ⊕ R4)
        int a1 = getBit2(L0, 5)^getBit2(R0, 5)^getBit2(L4, 5)
                ^getBit2(L0, 13)^getBit2(R0, 13)^getBit2(L4, 13)
                ^getBit2(L0, 21)^getBit2(R0, 21)^getBit2(L4, 21);

        // S15 F(L0 ⊕ F(L0 ⊕ R0 ⊕ K0) ⊕ K1)
        int y0 = Integer.reverseBytes(FEALLinear.f(Integer.reverseBytes(L0^R0^k0)));
        int y1 = Integer.reverseBytes(FEALLinear.f(Integer.reverseBytes(L0^y0^k1)));
        int a2 = getBit2(Integer.reverseBytes(FEALLinear.f(Integer.reverseBytes(L0^R0^y1^key))), 15);

        // a = a1⊕a2
        return a1 ^ a2;
    }

    static int calculateConstOutteBytesk2(int wordIndex, int key, int k0, int k1) {
        // Split pairs
        int L0 = getLeft(plaintext[wordIndex]);
        int R0 = getRigth(plaintext[wordIndex]);
        int L4 = getLeft(cyphertext[wordIndex]);
        int R4 = getRigth(cyphertext[wordIndex]);

        // S13(L0 ⊕ R4)
        int a1 = getBit2(L0, 13)^getBit2(R0, 13)^getBit2(L4, 13);

        // S7,15,23,31 F(L0 ⊕ F(L0 ⊕ R0 ⊕ K0) ⊕ K1)
        int y0 = Integer.reverseBytes(FEALLinear.f(Integer.reverseBytes(L0^R0^k0)));
        int y1 = Integer.reverseBytes(FEALLinear.f(Integer.reverseBytes(L0^y0^k1)));
        int y2 = Integer.reverseBytes(FEALLinear.f(Integer.reverseBytes(L0^R0^y1^key)));
        int a2 = getBit2(y2, 7)
                ^getBit2(y2, 15)
                ^getBit2(y2, 23)
                ^getBit2(y2, 31);

        // a = a1⊕a2
        return a1^a2;
    }

    static int calculateConstInnerBytesk3(int wordIndex, int key, int k0, int k1, int k2) {
        // Split pairs
        int L0 = getLeft(plaintext[wordIndex]);
        int R0 = getRigth(plaintext[wordIndex]);
        int L4 = getLeft(cyphertext[wordIndex]);
        int R4 = getRigth(cyphertext[wordIndex]);

        // S13(L0 ⊕ R4)
        int a1 = getBit2(L0, 5)^getBit2(L4, 5)^getBit2(R4, 5)
                ^getBit2(L0, 13)^getBit2(L4, 13)^getBit2(R4, 13)
                ^getBit2(L0, 21)^getBit2(L4, 21)^getBit2(R4, 21);

        // S7,15,23,31 F(L0 ⊕ F(L0 ⊕ R0 ⊕ K0) ⊕ K1)
        int a2 = getBit2(L0, 15)^getBit2(R0, 15)^getBit2(L4, 15);


        int y0 = Integer.reverseBytes(FEALLinear.f(Integer.reverseBytes(L0^R0^k0)));
        int y1 = Integer.reverseBytes(FEALLinear.f(Integer.reverseBytes(L0^y0^k1)));
        int y2 = Integer.reverseBytes(FEALLinear.f(Integer.reverseBytes(L0^R0^y1^k2)));
        int y3 = Integer.reverseBytes(FEALLinear.f(Integer.reverseBytes(L0^y0^y2^key)));
        int a3 = getBit2(y3, 15);

        // a = a1⊕a2
        return a1^a2^a3;
    }

    static int calculateConstOutteBytesk3(int wordIndex, int key, int k0, int k1, int k2) {
        // Split pairs
        int L0 = getLeft(plaintext[wordIndex]);
        int R0 = getRigth(plaintext[wordIndex]);
        int L4 = getLeft(cyphertext[wordIndex]);
        int R4 = getRigth(cyphertext[wordIndex]);

        // S13(L0 ⊕ R4)
        int a1 = getBit2(L0, 13)^getBit2(L4, 13)^getBit2(R4, 13);

        // S7,15,23,31 F(L0 ⊕ F(L0 ⊕ R0 ⊕ K0) ⊕ K1)
        int a2 = getBit2(L0, 7)^getBit2(R0, 7)^getBit2(L4, 7)
                ^getBit2(L0, 15)^getBit2(R0, 15)^getBit2(L4, 15)
                ^getBit2(L0, 23)^getBit2(R0, 23)^getBit2(L4, 23)
                ^getBit2(L0, 31)^getBit2(R0, 31)^getBit2(L4, 31);


        int y0 = Integer.reverseBytes(FEALLinear.f(Integer.reverseBytes(L0^R0^k0)));
        int y1 = Integer.reverseBytes(FEALLinear.f(Integer.reverseBytes(L0^y0^k1)));
        int y2 = Integer.reverseBytes(FEALLinear.f(Integer.reverseBytes(L0^R0^y1^k2)));
        int y3 = Integer.reverseBytes(FEALLinear.f(Integer.reverseBytes(L0^y0^y2^key)));
        int a3 = getBit2(y3, 7)^getBit2(y3, 15)^getBit2(y3, 23)^getBit2(y3, 31);

        // a = a1⊕a2
        return a1^a2^a3;
    }

    private static void testKeys(int key0, int key1, int key2, int key3) {
        int L0 = getLeft(plaintext[0]);
        int R0 = getRigth(plaintext[0]);
        int L4 = getLeft(cyphertext[0]);
        int R4 = getRigth(cyphertext[0]);

        int y0 = Integer.reverseBytes(FEALLinear.f(Integer.reverseBytes(L0^R0^key0)));
        int y1 = Integer.reverseBytes(FEALLinear.f(Integer.reverseBytes(L0^y0^key1)));
        int y2 = Integer.reverseBytes(FEALLinear.f(Integer.reverseBytes(L0^R0^y1^key2)));
        int y3 = Integer.reverseBytes(FEALLinear.f(Integer.reverseBytes(L0^y0^y2^key3)));

        int left = L0^R0^y1^y3;

        int key4 = left^L4;
        int key5 = left^L0^y0^y2^R4;

        key0 = Integer.reverseBytes(key0);
        key1 = Integer.reverseBytes(key1);
        key2 = Integer.reverseBytes(key2);
        key3 = Integer.reverseBytes(key3);
        key4 = Integer.reverseBytes(key4);
        key5 = Integer.reverseBytes(key5);

        byte[] data = new byte[8];
        int key[] = {key0, key1, key2, key3, key4, key5};

        for(int w=0; w<text_count; w++) {
            String p_word = plaintext[w];
            String c_word = cyphertext[w];

            for (int i=0;i<8;i++)
                data[i] = (byte)(Integer.parseInt(p_word.substring(i * 2, (i * 2) + 2),16)&255);

            FEALLinear.encrypt(data, key);

            StringBuilder sb = new StringBuilder(data.length * 2);
            for(byte b: data)
                sb.append(String.format("%02x", b));

            if(!c_word.equals(sb.toString()))
                return;
        }

        System.out.println("K0: " + Integer.toHexString(key0));
        System.out.println("K1: " + Integer.toHexString(key1));
        System.out.println("K2: " + Integer.toHexString(key2));
        System.out.println("K3: " + Integer.toHexString(key3));
        System.out.println("K4: " + Integer.toHexString(key4));
        System.out.println("K5: " + Integer.toHexString(key5));
        System.out.println("************ Profit ************");

    }

    private static void attackK3(int key0, int key1, int key2){

        Set<Integer> candidateKeysk3 = new HashSet<Integer>();
        Set<Integer> candidateKeysk3T = new HashSet<Integer>();

        for(int k=0; k<4096; k++) {
            int key_tilda = generate12BitKeyForInnerBytes(k);
            int first_a = calculateConstInnerBytesk3(0, key_tilda, key0, key1, key2);

            for(int w=1; w<text_count; w++) {
                if(first_a != calculateConstInnerBytesk3(w, key_tilda,  key0, key1, key2))
                    break;

                if(w == text_count-1 && !candidateKeys.contains(key_tilda)) {
                    // System.out.println(getBitString(key));
                    candidateKeysk3T.add(key_tilda);
                }
            }
        }

        for(int k=0; k<18576; k++) {
            for(int key_tilda: candidateKeysk3T) {
                int key3 = generate20BitKeyForOutterBytes(k, key_tilda);
                    int first_a = calculateConstOutteBytesk3(0, key3, key0, key1, key2);

                    for(int w=1; w<text_count; w++) {
                        if(first_a != calculateConstOutteBytesk3(w, key3, key0, key1, key2))
                            break;

                        if(w == text_count-1) {
                            // System.out.println(getBitString(Integer.reverseBytes(key)));
                            candidateKeysk3.add(key3);
                            testKeys(key0, key1, key2, key3);
                        }
                    }
            }
        }
    }

    public static void main(String [] args) {
        readKnownTextPairs();

        System.out.println("K0~");

        for(int k=0; k<4096; k++) {
            int key = generate12BitKeyForInnerBytes(k);
            int first_a = calculateConstInnerBytes(0, key);

            // 200 equals number of pairs
            for(int w=1; w<text_count; w++) {
                if(first_a != calculateConstInnerBytes(w, key))
                    break;

                if(w == text_count-1) {
                    System.out.println(getBitString(key));
                    candidateKeys.add(key);
                }
            }
        }

        Set<Integer> candidateKeysk0 = new HashSet<Integer>();

        System.out.println("K0");

        for(int k=0; k<1048576; k++) {
            for(int key_tilda: candidateKeys) {
                int key = generate20BitKeyForOutterBytes(k, key_tilda);
                int first_a = calculateConstOutteBytes(0, key);

                for(int w=1; w<text_count; w++) {
                    if(first_a != calculateConstOutteBytes(w, key))
                        break;

                    if(w == text_count-1) {
                        System.out.println(getBitString(Integer.reverseBytes(key)));
                        candidateKeysk0.add(key);
                    }
                }
            }
        }


        System.out.println("K1~");

        candidateKeys = new HashSet<Integer>();

        for(int k=0; k<4096; k++) {
            int key = generate12BitKeyForInnerBytes(k);

            for(int key0: candidateKeysk0) {

                int first_a = calculateConstInnerBytesk1(0, key, key0);

                for(int w=1; w<text_count; w++) {
                    if(first_a != calculateConstInnerBytesk1(w, key, key0))
                        break;

                    if(w == text_count-1) {
                        System.out.println(getBitString(key));
                        candidateKeys.add(key);
                    }
                }
            }
        }

        Set<Integer> candidateKeysk1 = new HashSet<Integer>();

        System.out.println("K1");

        for(int k=0; k<18576; k++) {
            for(int key_tilda: candidateKeys) {
                int key = generate20BitKeyForOutterBytes(k, key_tilda);

                for(int key0: candidateKeysk0) {
                    int first_a = calculateConstOutteBytesk1(0, key, key0);

                    for(int w=1; w<text_count; w++) {
                        if(first_a != calculateConstOutteBytesk1(w, key, key0))
                            break;

                        if(w == text_count-1) {
                            System.out.println(getBitString(Integer.reverseBytes(key)));
                            candidateKeysk1.add(key);
                        }
                    }
                }
            }
        }

        System.out.println("K2~");

        candidateKeys = new HashSet<Integer>();

        for(int k=0; k<4096; k++) {
            int key = generate12BitKeyForInnerBytes(k);

            for(int key0: candidateKeysk0) {

                for(int key1: candidateKeysk1) {

                    int first_a = calculateConstInnerBytesk2(0, key, key0, key1);

                    for(int w=1; w<text_count; w++) {
                        if(first_a != calculateConstInnerBytesk2(w, key,  key0, key1))
                            break;

                        if(w == text_count-1 && !candidateKeys.contains(key)) {
                            System.out.println(getBitString(key));
                            candidateKeys.add(key);
                        }
                    }
                }
            }
        }


        Set<Integer> candidateKeysk2 = new HashSet<Integer>();

        System.out.println("K2");

        for(int k=0; k<18576; k++) {
            for(int key_tilda: candidateKeys) {
                int key = generate20BitKeyForOutterBytes(k, key_tilda);

                for(int key0: candidateKeysk0) {
                    for(int key1: candidateKeysk1) {
                        int first_a = calculateConstOutteBytesk2(0, key, key0, key1);

                        for(int w=1; w<text_count; w++) {
                            if(first_a != calculateConstOutteBytesk2(w, key, key0, key1))
                                break;

                            if(w == text_count-1) {
                                // System.out.println(getBitString(Integer.reverseBytes(key)));
                                candidateKeysk2.add(key);
                                attackK3(key0, key1, key);
                            }
                        }
                    }
                }
            }
        }

        // System.out.println("K3~");
        //
        // candidateKeys = new HashSet<Integer>();
        //
        // for(int k=0; k<4096; k++) {
        //     int key = generate12BitKeyForInnerBytes(k);
        //
        //     for(int key0: candidateKeysk0) {
        //
        //         for(int key1: candidateKeysk1) {
        //
        //             for(int key2: candidateKeysk2) {
        //
        //                 int first_a = calculateConstInnerBytesk3(0, key, key0, key1, key2);
        //
        //                 for(int w=1; w<text_count; w++) {
        //                     if(first_a != calculateConstInnerBytesk3(w, key,  key0, key1, key2))
        //                         break;
        //
        //                     if(w == text_count-1 && !candidateKeys.contains(key)) {
        //                         System.out.println(getBitString(key));
        //                         candidateKeys.add(key);
        //                     }
        //                 }
        //             }
        //         }
        //     }
        // }
        //
        // Set<Integer> candidateKeysk3 = new HashSet<Integer>();
        //
        // System.out.println("K3");
        //
        // for(int k=0; k<18576; k++) {
        //     for(int key_tilda: candidateKeys) {
        //         int key3 = generate20BitKeyForOutterBytes(k, key_tilda);
        //
        //         for(int key0: candidateKeysk0) {
        //             for(int key1: candidateKeysk1) {
        //                 for(int key2: candidateKeysk2) {
        //                     int first_a = calculateConstOutteBytesk3(0, key3, key0, key1, key2);
        //
        //                     for(int w=1; w<text_count; w++) {
        //                         if(first_a != calculateConstOutteBytesk3(w, key3, key0, key1, key2))
        //                             break;
        //
        //                         if(w == text_count-1) {
        //                             // System.out.println(getBitString(Integer.reverseBytes(key)));
        //                             candidateKeysk3.add(key3);
        //                             testKeys(key0, key1, key2, key3);
        //                         }
        //                     }
        //                 }
        //             }
        //         }
        //     }
        // }
    }
}
