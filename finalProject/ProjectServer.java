//-----University of Maryland, College Park-----
//ENTS 640 - Networks and Protocols
//Submitted to Dr. Zoltan Safar on 28 November 2015.
//Authors : Akshay Prasad(114252500) & Ashish Kashyap(114396742)
package finalProject;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;

public class ProjectServer {
	static final int mps = 30;
	private static int dataPayLoad;
	static final int packetTypeLength = 1;
	static final int sequenceNumberLength = 4;
	static final int length = 1;
	static final int integrityCheckLength = 4;
	static final int acknowledgementNo = 4;	
	static final int timeOutPeriod=1000;
	private static byte packetType;
	private static byte[] seqNo = new byte[sequenceNumberLength];
	private static byte lengthOfPacket;
	private static byte data[];
	private static byte[] integrityCheckCode = new byte[integrityCheckLength];
	
	public static byte getPacketType(){
		return packetType;
	}
	
	public static byte getLengthOfPacket(){
		return lengthOfPacket;
	}
	public static byte[] getSeqNo(){
		return seqNo;
	}
	public static byte[] getData(){
		return data;
	}
	public static byte[] getIntegrityCheckCode(){
		return integrityCheckCode;
	}
	
	public static void setPacketType(byte packet){
		packetType=packet;
	}
	
	public static void setLengthOfPacket(byte length){
		lengthOfPacket=length;
	}
	public static void setSeqNo(byte[] seq){
		seqNo=seq;
	}
	public static void setData(byte[] newData){
		data = newData;
	}
	public static void setIntegrityCheckCode(byte[] code){
		integrityCheckCode = code;
	}
	
	public static byte[] combine(int check) throws IOException{
		if(check==0){
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
			outputStream.write( getPacketType() );
			outputStream.write( getLengthOfPacket() );
			outputStream.write( getSeqNo() );
			outputStream.write( getData() );
			outputStream.write( getIntegrityCheckCode() );
			byte message[] = outputStream.toByteArray( );
			return message;
		}
		else{
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
			outputStream.write( packetType );
			outputStream.write( lengthOfPacket );
			outputStream.write( seqNo );
			outputStream.write( data );
			byte message[] = outputStream.toByteArray( );
			return message;
		}	
	}
	
	public static void main(String[] args) throws Exception{
		byte key[] = new byte[]{12,17,78,41,51,90,1,7,8,9,11,13,5,9,1,19};//Generating Key 
		byte seqNo[] = new byte[]{14,19,10,55};
		setSeqNo(seqNo);
		DatagramSocket serverSocket = new DatagramSocket(1999);
		while(true){
			byte[] rByte = null;
			DatagramPacket recPacket = new DatagramPacket(rByte, rByte.length);
			serverSocket.receive(recPacket);                                    
			InetAddress IPAddress = recPacket.getAddress();                   
			int port = recPacket.getPort();         
			rByte=recPacket.getData();
		}
	}

}
