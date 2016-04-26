//-----University of Maryland, College Park-----
//ENTS 640 - Networks and Protocols
//Submitted to Dr. Zoltan Safar on 30 November 2015.
//Authors : Akshay Prasad(114252500) & Ashish Kashyap(114395702)

package finalProjectServer;
import java.security.SecureRandom;

import finalProjectServer.RC4;

public class IntegrityCheck {
	//This particular method is used to calculate the integrity check and uses the input text and key to call the RC4 encrypt
	//method. Prior to encrypting the text, the method calls another method called pad() to pad the given input text with zeros
	//such that the length of the padded text is a multiple of 4.
	public static byte[] calculateCheck(byte[] input,byte key[]){
		input=pad(input);
		int size = input.length;
		byte c0=0,c1=0,c2=0,c3=0;
		byte returnCheck[] = new byte[4];
		//If the length of input text is not a multiple of 4, the method pads the given text.
		if(size%4!=0){
			input=pad(input);
		}
		byte encrypted[];
		encrypted= RC4.encrypt(key,input);
		int i=4;//counter used to traverse through the encrypted text in steps of 4.
		c0=encrypted[0];
		c1=encrypted[1];
		c2=encrypted[2];
		c3=encrypted[3];
		while(i<encrypted.length){
			//c0-c4 are the 4 output bytes.
			//Then, C[0], the first byte of the integrity check value,
			//should be calculated as the bit-wise exclusive or (XOR) of the bytes b[0], b[4], b[8], ..., i.e.
			//every fourth byte starting from the first byte. C[1], the second byte of the integrity check
			//value, should be the XOR of the bytes b[1], b[5], b[9] and so on.
			c0=(byte) (c0^encrypted[i]);
			c1=(byte) (c1^encrypted[i+1]);
			c2=(byte) (c2^encrypted[i+2]);
			c3=(byte) (c3^encrypted[i+3]);
			i+=4;
		}
		returnCheck[0]=c0;
		returnCheck[1]=c1;
		returnCheck[2]=c2;
		returnCheck[3]=c3;
		return returnCheck;
		
	}
	
	public static byte[] pad(byte[] padInput){
		int length = padInput.length;
		int padCtr=0;
		while(length%4!=0){
			padCtr+=1;
			length=length+1;
		}
		length=padInput.length;
		//New byte array with incremented length is created.
		byte paddedInput[] = new byte[length+padCtr];
		for(int i=0;i<length+padCtr;i++){
			//Data is copied from old array to new array until there is data to be copied after which 0s are stored in the remaining
			//positions.
			if(i<length)
				paddedInput[i]=padInput[i];
			else
				paddedInput[i]=(byte)0;
		}	
		return paddedInput;
	}

}
