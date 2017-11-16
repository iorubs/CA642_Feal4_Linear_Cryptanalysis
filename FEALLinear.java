/*
 * The FEAL cipher
 */

import java.util.Arrays;
import java.lang.Byte;

public class FEALLinear {
    
    static int rounds = 4;
    
    static byte rot2(byte x) {
        return (byte)(((x&255)<<2)|((x&255)>>>6));
    }
    
    static byte g0(byte a,byte b) {
        return rot2((byte)((a+b)&255));
    }

    static byte g1(byte a,byte b) {
        return rot2((byte)((a+b+1)&255));
    }
    
    static int pack(byte[] b,int startindex) {
       /* pack 4 bytes into a 32-bit Word */
       return (((b[startindex+3]&255)<<24)|((b[startindex+2]&255)<<16)|((b[startindex+1]&255)<<8)|(b[startindex]&255));
    }

    static void unpack(int a,byte[] b,int startindex) {
        /* unpack bytes from a 32-bit word */
        
        b[startindex]=(byte)a;
        b[startindex+1]=(byte)(a>>>8);
        b[startindex+2]=(byte)(a>>>16);
        b[startindex+3]=(byte)(a>>>24);
    }

    static int f(int input) {
        byte[] x = new byte[4];
        byte[] y = new byte[4];
        
        unpack(input,x,0);
        y[1]=g1((byte)((x[0]^x[1])&255),(byte)((x[2]^x[3])&255));
        y[0]=g0((byte)(x[0]&255),(byte)(y[1]&255));
        y[2]=g0((byte)(y[1]&255),(byte)((x[2]^x[3])&255));
        y[3]=g1((byte)(y[2]&255),(byte)(x[3]&255));
        return pack(y,0);
    }

    static void encrypt(byte data[],int key[]) {
        int left,right,temp;
        
        left=pack(data,0);
        right=left^pack(data,4);
        
        for (int i=0;i<rounds;i++) {
            temp=right;
            right=left^f(right^key[i]);
            left=temp;
        }

        temp=left;
        left=right^key[4];
        right=temp^right^key[5];

        unpack(left,data,0);
        unpack(right,data,4);
    }

    static void decrypt(byte data[],int key[]) {
        int left,right,temp;

        right=pack(data,0)^key[4];
        left=right^pack(data,4)^key[5];
        
        for (int i=0;i<rounds;i++) {
            temp=left;
            left=right^f(left^key[rounds-1-i]);
            right=temp;
        }

        right^=left;

        unpack(left,data,0);
        unpack(right,data,4);
    }

    public static void main(String args[]) {
        byte[] data = new byte[8];
        
        /* Not the keys you are looking for!!! */
        int key[]={0x0,0x0,0x0,0x0,0x0,0x0};
  
        if (args.length!=8) {
            System.out.println("command line error - input 8 bytes of plaintext in hex");
            System.out.println("For example:");
            System.out.println("java feal 0 1 2 3 4e 5a f6 37");
            return;
        }
        for (int i=0;i<8;i++)
            data[i] = (byte)(Integer.parseInt(args[i],16)&255);

        System.out.print("Plaintext=  ");
        for (int i=0;i<8;i++) System.out.printf("%02x",data[i]);
        System.out.print("\n");

        encrypt(data,key);
        System.out.print("Ciphertext= ");
        for (int i=0;i<8;i++) System.out.printf("%02x",data[i]);
        System.out.print("\n");

        decrypt(data,key);
        System.out.print("Plaintext=  ");
        for (int i=0;i<8;i++) System.out.printf("%02x",data[i]);
        System.out.print("\n");

        return;
    }
}
