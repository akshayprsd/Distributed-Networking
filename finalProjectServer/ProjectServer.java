//-----University of Maryland, College Park-----
//ENTS 640 - Networks and Protocols
//Submitted to Dr. Zoltan Safar on 30 November 2015.
//Authors : Akshay Prasad(114252500) & Ashish Kashyap(114395702)
package finalProjectServer;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.Arrays;

public class ProjectServer {
	//Initializing private data fields
	static final int mps = 30;//Maximum packet size
	private static int dataPayLoad;//Size of data field
	static final int packetTypeLength = 1;//size of packet length field in the packet
	static final int sequenceNumberLength = 4;//size of sequence number field in the packet
	static final int length = 1;
	static final int integrityCheckLength = 4;//size of integrity check field in the packet
	static final int acknowledgementNo = 4;	//size of acknowledgement number field in the packet
	static final int timeOutPeriod=1000;//Time out Period
	private static byte packetType;
	private static byte[] seqNo = new byte[sequenceNumberLength];
	private static byte lengthOfPacket;
	private static byte data[];
	private static byte[] integrityCheckCode = new byte[integrityCheckLength];
	//Accessor Functions
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
	//Mutator functions
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
	
	//This function is used to add data to final byte array storing all the data that has been received.
	public static byte[] combine(byte[] original, byte[] add) throws IOException{
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
		outputStream.write(original);
		outputStream.write(add);
		byte message[] = outputStream.toByteArray( );
		return message;
		
		
	}
	//This function is used to extract the data field from a received byte array. 
	public static byte[] extractData(byte[] input,int length) throws IOException{
		return Arrays.copyOfRange(input,6, 6+length);//The data field starts at the 6th position in the received byte array.
	}
	
	public static void main(String[] args) throws Exception{
		byte key[] = new byte[]{12,17,78,41,51,90,1,7,8,9,11,13,5,9,1,19};//Predefined key and Sequence number
		byte setSeqNo[] = new byte[]{14,19,10,55};
		byte finalData[]=new byte[]{0};
		setSeqNo(setSeqNo);
		int intSeqNo=ByteBuffer.wrap(seqNo).getInt();
		DatagramSocket serverSocket = new DatagramSocket(1993);
		while(true){               
			byte[] rByte = new byte[40];
			DatagramPacket recPacket = new DatagramPacket(rByte, rByte.length);
			serverSocket.receive(recPacket); 
			InetAddress IPAddress = recPacket.getAddress();                   
			int port = recPacket.getPort();         
			rByte=recPacket.getData();
			System.out.print("\nPacket Received :" +Arrays.toString(rByte));
			byte tempData[]=extractData(rByte,rByte[5]);//Extracts data field from the received packet byte array.
			byte recCheck[]=Arrays.copyOfRange(rByte, 6+rByte[5], 6+rByte[5]+4);//Extracts the Integrity check from the received byte array.
			System.out.print("\nReceived Integrity Check :" +Arrays.toString(recCheck));
			byte tempCheck[]=Arrays.copyOfRange(rByte,0, 6+rByte[5]);//Extracts the Integrity Check from the received byte array.
			byte tempIntegrityCheck[]=IntegrityCheck.calculateCheck(tempCheck,key);
			System.out.print("\nCaclulated Integrity Check :" +Arrays.toString(tempIntegrityCheck));
			byte recSeqNo[]=Arrays.copyOfRange(rByte, 1, 5);//Extracts the Sequence Number from the received byte array.
			System.out.print("\nReceived Sequence Number :" +Arrays.toString(recSeqNo));
			if(Arrays.equals(tempIntegrityCheck, recCheck)){
				System.out.print("\nIntegrity Check Matches!");
				if(Arrays.equals(recSeqNo, getSeqNo())){
					System.out.print("\nSequence Number Matches!");
					if(rByte.length-10<=mps){
						System.out.print("\nLength of Packet Appropriate!");
						if((rByte[0]==(byte)0x55)||(rByte[0]==(byte)0xaa)){
							System.out.print("\nPacket Type Matches!");
							//Following if-else statement is used to distinguish between the last packet or a regular packet based on the
							//packet type field in the received byte array.
							if(rByte[0]==(byte)0xaa){
								//Preparing acknowledgement packet
								byte[] sendBuffer=new byte[]{0};
								sendBuffer[0]=(byte)0xff;//Assigns packet type
								intSeqNo+=rByte[5];
								byte[] newSeqNo = ByteBuffer.allocate(4).putInt(intSeqNo).array();
								setSeqNo(newSeqNo);
								sendBuffer=combine(sendBuffer,getSeqNo());//Assigns acknowledgement number.
								tempIntegrityCheck=IntegrityCheck.calculateCheck(sendBuffer,key);//Calculates Integrity Check
								sendBuffer=combine(sendBuffer,tempIntegrityCheck);//Assigns Integrity Check
								DatagramPacket sendPacket = new DatagramPacket(sendBuffer, sendBuffer.length, IPAddress, port);  
								serverSocket.send(sendPacket); 
								System.out.print("\nAcknowledgement  Packet Sent :" +Arrays.toString(sendBuffer));
								finalData=combine(finalData,tempData);
								System.out.println("\nReceived Data : " + Arrays.toString(Arrays.copyOfRange(finalData,1,finalData.length)));
							}
							else{
								//Preparing acknowledgement packet
								byte[] sendBuffer=new byte[]{0};
								finalData=combine(finalData,tempData);
								sendBuffer[0]=(byte)0xff;//Assigns packet type
								intSeqNo+=rByte[5];
								byte[] newSeqNo = ByteBuffer.allocate(4).putInt(intSeqNo).array();
								setSeqNo(newSeqNo);
								sendBuffer=combine(sendBuffer,getSeqNo());//Assigns acknowledgement number.
								tempIntegrityCheck=IntegrityCheck.calculateCheck(sendBuffer,key);//Calculates Integrity Check
								sendBuffer=combine(sendBuffer,tempIntegrityCheck);//Assigns Integrity Check
								DatagramPacket sendPacket = new DatagramPacket(sendBuffer, sendBuffer.length, IPAddress, port);  
								serverSocket.send(sendPacket); 
								System.out.println("\nAcknowledgement Packet Sent :" +Arrays.toString(sendBuffer));
								finalData=combine(finalData,tempData);
								
							}
						 }
						else System.out.print("\nPacket Type Mismatch!");
					  }
					else System.out.print("\nLength of Payload > MPS");
					}
				else System.out.print("\nSequence Number Mismatch!");
				}
			else System.out.print("\nIntegrity Check Mismatch!");
			}
		}
	}


					