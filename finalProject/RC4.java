//-----University of Maryland, College Park-----
//ENTS 640 - Networks and Protocols
//Submitted to Dr. Zoltan Safar on 30 November 2015.
//Authors : Akshay Prasad(114252500) & Ashish Kashyap(114395702)
//ENTS 640 - Networks and Protocols

package finalProject;
public class RC4 {
//This particular method is used to encrypt a given array of data using a given key.
public static byte[] encrypt(byte[] key, byte[] input) {
    int keyLength = key.length;
    int dataLength = input.length;
 
    //Initialization of S. The entries of S are set equal to the values from 0 through 255 in ascending order; that
    //is; S[0] = 0, S[1] = 1, …, S[255] = 255.
    byte[] s = new byte[256];
    int i;int j = 0;
    for(i = 0; i < 256; i++) {
        s[i] = (byte)i;
    }   
    //This involves starting with S[0] and going through to S[255], and, for each S[i], swapping S[i] with another byte in S according to a scheme dictated by T[i]
    //Skipping the initialization of T and introducing the step by initializing j appropriately. T[i] = K[i mod keylen];
    //Permutation is done as : j = (j + S[i] + T[i]) mod 256;
    for(i = 0; i < 256; i++) {
        j = ((j + s[i] + key[i % keyLength]) % 256) & 0xFF;
        byte tmp = s[i];
        s[i] = s[j];
        s[j] = tmp;
    }
    i = 0;
    j = 0;
    int ctr = 0;
    //After S has been created, the key will no longer be used and S will be used to generate the stream.
    ///* Stream Generation */
    //i = (i + 1) mod 256;
    //j = (j + S[i]) mod 256;
    //Swap (S[i], S[j]);
    //t = (S[i] + S[j]) mod 256;
    //k = S[t];
    //The encrypted text is obtained by Xoring k with the plaintext.
    while(ctr < dataLength) {
        i = ((i + 1) % 256) & 0xFF;
        j = ((j + s[i]) % 256) & 0xFF;
        byte tmp = s[i];
        s[i] = s[j];
        s[j] = tmp;
        byte k = (byte)(s[((s[i] + s[j]) % 256) & 0xFF]);
        input[ctr] ^= k;
        input[ctr] = (byte) (input[ctr]&0xff); 
        ctr++;
    }
    return input;
  }
}


