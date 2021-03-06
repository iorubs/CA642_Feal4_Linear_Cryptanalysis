import java.io.*;

public class MyFealLinear {
    private static int L0, R0, L4, R4;
    private static int num_pairs = 200;
    private static String plaintext[] = new String[num_pairs];
    private static String cyphertext[] = new String[num_pairs];

    private static int getBit(int num, int n) {
        return (num >> (31-n)) & 1;
    }

    private static void splitPairs(int wordIndex) {
        L0 = (int) Long.parseLong(plaintext[wordIndex].substring(0,8), 16);
        R0 = (int) Long.parseLong(plaintext[wordIndex].substring(8), 16);
        L4 = (int) Long.parseLong(cyphertext[wordIndex].substring(0,8), 16);
        R4 = (int) Long.parseLong(cyphertext[wordIndex].substring(8), 16);
    }

    private static int f(int num) {
        return Integer.reverseBytes(FEALLinear.f(Integer.reverseBytes(num)));
    }

    private static void readKnownTextPairs() {
        try {
            BufferedReader bufferedReader = new BufferedReader(new FileReader("known_geoff.txt"));
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
        catch(FileNotFoundException e) { System.out.println("Could not find input file."); }
        catch(IOException e) { System.out.println("Unable to read input file: IOException"); }
    }

    private static int generate12BitKeyForInnerBytes(int k) {
        return (((k >> 6) & 0x3F) << 16) + ((k & 0x3F) << 8) ;
    }

    private static int generate20BitKeyForOutterBytes(int k, int key_tilda) {
        int a0 = (((k & 0xF) >> 2) << 6) + ((key_tilda >> 16) & 0xFF);
        int a1 = ((k & 0x3) << 6) + ((key_tilda >> 8) & 0xFF);

        int b0 = (k >> 12) & 0xFF;
        int b3 = (k >> 4) & 0xFF;

        int b1 = b0^a0;
        int b2 = b3^a1;

        return (b0 << 24)  + (b1 << 16) + (b2 << 8) + b3;
    }

    static int calculateConstInnerBytesk0(int wordIndex, int key) {
        splitPairs(wordIndex);

        // S5,13,21(L0 ⊕ R0 ⊕ L4)
        int a1 = getBit(L0^R0^L4, 5)^getBit(L0^R0^L4, 13)^getBit(L0^R0^L4, 21);

        // S15(L0 ⊕ L4 ⊕ R4)
        int a2 = getBit(L0^L4^R4, 15);

        // S15 F(L0 ⊕ R0 ⊕ K0)
        int a3 = getBit(f(L0^R0^key), 15);

        return a1^a2^a3;
    }

    static int calculateConstOutteBytesk0(int wordIndex, int key) {
        splitPairs(wordIndex);

        // S13(L0 ⊕ R0 ⊕ L4)
        int a1 = getBit(L0^R0^L4, 13);

        // S7,15,23,31(L0 ⊕ L4 ⊕ R4)
        int a2 = getBit(L0^L4^R4, 7)^getBit(L0^L4^R4, 15)^getBit(L0^L4^R4, 23)^getBit(L0^L4^R4, 31);

        // S7,15,23,31 F(L0 ⊕ R0 ⊕ K0)
        int y0 = f(L0^R0^key);
        int a3 = getBit(y0, 7)^getBit(y0, 15)^getBit(y0, 23)^getBit(y0, 31);

        return a1^a2^a3;
    }

    static int calculateConstInnerBytesk1(int wordIndex, int key, int k0) {
        splitPairs(wordIndex);

        // S5,13,21(L0 ⊕ L4 ⊕ R4)
        int a1 = getBit(L0^L4^R4, 5)^getBit(L0^L4^R4, 13)^getBit(L0^L4^R4, 21);

        // S15 F(L0 ⊕ F(L0 ⊕ R0 ⊕ K0) ⊕ K1)
        int y0 = f(L0^R0^k0);
        int a2 = getBit(f(L0^y0^key), 15);

        return a1^a2;
    }

    static int calculateConstOutteBytesk1(int wordIndex, int k0, int k1) {
        splitPairs(wordIndex);

        // S13(L0 ⊕ L4 ⊕ R4)
        int a1 = getBit(L0^L4^R4, 13);

        // S7,15,23,31 F(L0 ⊕ F(L0 ⊕ R0 ⊕ K0) ⊕ K1)
        int y0 = f(L0^R0^k0);
        int y1 = f(L0^y0^k1);
        int a2 = getBit(y1, 7)^getBit(y1, 15)^getBit(y1, 23)^getBit(y1, 31);

        return a1^a2;
    }

    private static void attackK1(int key0) {
        for(int k1=0; k1<4096; k1++) {
            int key_tilda = generate12BitKeyForInnerBytes(k1);
            int first_a1 = calculateConstInnerBytesk1(0, key_tilda, key0);

            for(int w1=1; w1<num_pairs; w1++) {
                if(first_a1 != calculateConstInnerBytesk1(w1, key_tilda,  key0))
                    break;

                if(w1 == num_pairs-1) {
                    for(int k2=0; k2<1048576; k2++) {
                        int key1 = generate20BitKeyForOutterBytes(k2, key_tilda);
                        int first_a2 = calculateConstOutteBytesk1(0, key0, key1);

                        for(int w2=1; w2<num_pairs; w2++) {
                            if(first_a2 != calculateConstOutteBytesk1(w2, key0, key1))
                                break;

                            if(w2 == num_pairs-1)
                                attackK2(key0, key1);
                        }
                    }
                }
            }
        }
    }

    static int calculateConstInnerBytesk2(int wordIndex, int key, int k0, int k1) {
        splitPairs(wordIndex);

        // S5,13,21(L0 ⊕ R0⊕ L4)
        int a1 = getBit(L0^R0^L4, 5)^getBit(L0^R0^L4, 13)^getBit(L0^R0^L4, 21);

        // S15 F(L0 ⊕ R0 ⊕ F(L0 ⊕ F(L0 ⊕ R0 ⊕ K0) ⊕ K1) ⊕ K2)
        int y0 = f(L0^R0^k0);
        int y1 = f(L0^y0^k1);
        int a2 = getBit(f(L0^R0^y1^key), 15);

        return a1^a2;
    }

    static int calculateConstOutteBytesk2(int wordIndex, int k0, int k1, int k2) {
        splitPairs(wordIndex);

        // S13(L0 ⊕ R0 ⊕ L4)
        int a1 = getBit(L0^R0^L4, 13);

        // S7,15,23,31 F(L0 ⊕ R0 ⊕ F(L0 ⊕ F(L0 ⊕ R0 ⊕ K0) ⊕ K1) ⊕ K2)
        int y0 = f(L0^R0^k0);
        int y1 = f(L0^y0^k1);
        int y2 = f(L0^R0^y1^k2);
        int a2 = getBit(y2, 7)^getBit(y2, 15)^getBit(y2, 23)^getBit(y2, 31);

        return a1^a2;
    }

    private static void attackK2(int key0, int key1) {
        for(int k1=0; k1<4096; k1++) {
            int key_tilda = generate12BitKeyForInnerBytes(k1);
            int first_a1 = calculateConstInnerBytesk2(0, key_tilda, key0, key1);

            for(int w1=1; w1<num_pairs; w1++) {
                if(first_a1 != calculateConstInnerBytesk2(w1, key_tilda,  key0, key1))
                    break;

                if(w1 == num_pairs-1) {
                    for(int k2=0; k2<1048576; k2++) {
                        int key2 = generate20BitKeyForOutterBytes(k2, key_tilda);
                        int first_a2 = calculateConstOutteBytesk2(0, key0, key1, key2);

                        for(int w2=1; w2<num_pairs; w2++) {
                            if(first_a2 != calculateConstOutteBytesk2(w2, key0, key1, key2))
                                break;

                            if(w2 == num_pairs-1)
                                attackK3(key0, key1, key2);
                        }
                    }
                }
            }
        }
    }

    static int calculateConstInnerBytesk3(int wordIndex, int key, int k0, int k1, int k2) {
        splitPairs(wordIndex);

        // a1 = S5,13,21(L0 ⊕ L4 ⊕ R4)
        int a1 = getBit(L0^L4^R4, 5)^getBit(L0^L4^R4, 13)^getBit(L0^L4^R4, 21);

        // a2 = S15(L0 ⊕ R0 ⊕ L4)
        int a2 = getBit(L0^R0^L4, 15);

        // a3 = S15 F(L0 ⊕ F(L0 ⊕ R0 ⊕ K0) ⊕ F(L0 ⊕ R0 ⊕ F(L0 ⊕ F(L0 ⊕ R0 ⊕ K0) ⊕ K1) ⊕ K2) ⊕ K3)
        int y0 = f(L0^R0^k0);
        int y1 = f(L0^y0^k1);
        int y2 = f(L0^R0^y1^k2);
        int a3 = getBit(f(L0^y0^y2^key), 15);

        return a1^a2^a3;
    }

    static int calculateConstOutteBytesk3(int wordIndex, int k0, int k1, int k2, int k3) {
        splitPairs(wordIndex);

        // = S13(L0 ⊕ L4 ⊕ R4)
        int a1 = getBit(L0^L4^R4, 13);

        // S7,15,23,31(L0 ⊕ R0 ⊕ L4)
        int a2 = getBit(L0^R0^L4, 7)^getBit(L0^R0^L4, 15)^getBit(L0^R0^L4, 23)^getBit(L0^R0^L4, 31);

        // S7,15,23,31 F(L0 ⊕ F(L0 ⊕ R0 ⊕ K0) ⊕ F(L0 ⊕ R0 ⊕ F(L0 ⊕ F(L0 ⊕ R0 ⊕ K0) ⊕ K1) ⊕ K2) ⊕ K3)
        int y0 = f(L0^R0^k0);
        int y1 = f(L0^y0^k1);
        int y2 = f(L0^R0^y1^k2);
        int y3 = f(L0^y0^y2^k3);
        int a3 = getBit(y3, 7)^getBit(y3, 15)^getBit(y3, 23)^getBit(y3, 31);

        return a1^a2^a3;
    }

    private static void attackK3(int key0, int key1, int key2) {
        for(int k1=0; k1<4096; k1++) {
            int key_tilda = generate12BitKeyForInnerBytes(k1);
            int first_a1 = calculateConstInnerBytesk3(0, key_tilda, key0, key1, key2);

            for(int w1=1; w1<num_pairs; w1++) {
                if(first_a1 != calculateConstInnerBytesk3(w1, key_tilda,  key0, key1, key2))
                    break;

                if(w1 == num_pairs-1) {
                    for(int k2=0; k2<1048576; k2++) {
                        int key3 = generate20BitKeyForOutterBytes(k2, key_tilda);
                        int first_a2 = calculateConstOutteBytesk3(0, key0, key1, key2, key3);

                        for(int w2=1; w2<num_pairs; w2++) {
                            if(first_a2 != calculateConstOutteBytesk3(w2, key0, key1, key2, key3))
                                break;

                            if(w2 == num_pairs-1)
                                testKeys(key0, key1, key2, key3);
                        }
                    }
                }
            }
        }
    }

    private static void testKeys(int key0, int key1, int key2, int key3) {
        int y0 = f(L0^R0^key0);
        int y1 = f(L0^y0^key1);
        int y2 = f(L0^R0^y1^key2);
        int y3 = f(L0^y0^y2^key3);

        key0 = Integer.reverseBytes(key0);
        key1 = Integer.reverseBytes(key1);
        key2 = Integer.reverseBytes(key2);
        key3 = Integer.reverseBytes(key3);
        int key4 = Integer.reverseBytes(L0^R0^y1^y3^L4);
        int key5 = Integer.reverseBytes(R0^y1^y3^y0^y2^R4);

        int key[] = {key0, key1, key2, key3, key4, key5};
        byte[] data = new byte[8];

        for(int w=0; w<num_pairs; w++) {
            for (int i=0;i<8;i++)
                data[i] = (byte)(Integer.parseInt(cyphertext[w].substring(i * 2, (i * 2) + 2),16)&255);

            FEALLinear.decrypt(data, key);

            StringBuilder sb = new StringBuilder(data.length * 2);
            for(byte b: data)
                sb.append(String.format("%02x", b));

            if(!plaintext[w].equals(sb.toString()))
                return;
        }

        System.out.print("K0 0x" + Integer.toHexString(key0));
        System.out.print("\tK1 0x" + Integer.toHexString(key1));
        System.out.print("\tK2 0x" + Integer.toHexString(key2));
        System.out.print("\tK3 0x" + Integer.toHexString(key3));
        System.out.print("\tK4 0x" + Integer.toHexString(key4));
        System.out.println("\tK5 0x" + Integer.toHexString(key5));
        System.out.println("************ Profit ************");
    }

    public static void main(String [] args) {
        readKnownTextPairs();

        System.out.println("Start Linear Analysis of Feal 4");

        for(int k1=0; k1<4096; k1++) {
            int key_tilda = generate12BitKeyForInnerBytes(k1);
            int first_a1 = calculateConstInnerBytesk0(0, key_tilda);

            for(int w1=1; w1<num_pairs; w1++) {
                if(first_a1 != calculateConstInnerBytesk0(w1, key_tilda))
                    break;

                if(w1 == num_pairs-1) {
                    for(int k2=0; k2<1048576; k2++) {
                        int key0 = generate20BitKeyForOutterBytes(k2, key_tilda);
                        int first_a2 = calculateConstOutteBytesk0(0, key0);

                        for(int w2=1; w2<num_pairs; w2++) {
                            if(first_a2 != calculateConstOutteBytesk0(w2, key0))
                                break;

                            if(w2 == num_pairs-1)
                                attackK1(key0);
                        }
                    }
                }
            }
        }

        System.out.println("Finish Linear Analysis of Feal 4");
    }
}
