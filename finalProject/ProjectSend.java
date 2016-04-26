//-----University of Maryland, College Park-----
//ENTS 640 - Networks and Protocols
//Submitted to Dr. Zoltan Safar on 30 November 2015.
//Authors : Akshay Prasad(114252500) & Ashish Kashyap(114395702)
package finalProject;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;

public class ProjectSend{
	//Initializing private data fields
	static final int mps = 30;//Maximum packet size
	private static int dataPayLoad;//Size of data field
	static final int packetTypeLength = 1;//size of packet length field in the packet
	static final int sequenceNumberLength = 4;//size of sequence number field in the packet
	static final int length = 1;
	static final int integrityCheckLength = 4;//size of integrity check field in the packet
	static final int acknowledgementNo = 4;//size of acknowledgement number field in the packet
	static final int timeOutPeriod=500;//Time out Period
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
	public static byte[] getDataArr(){
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
	//This function is used to create packets to be sent. It uses 3 parameters. Check is used to define if the packet is being
	//combined for internal calculation i.e. for calculating integrity check prior to sending it to the server(check!=0) or if
	//the packet is being assembled for sending to the server i.e. it includes the integrity check field(check=0). The other
	//parameters ctr is used locate the position in the data stream from which the data needs to be copied. The payload
	//parameter is used to the size of the data field in the packet.
	public static byte[] combine(int check,int ctr, int payload) throws IOException{
		if(check==0){
			byte[] temp=Arrays.copyOfRange(getDataArr(), ctr, ctr+payload);
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
			outputStream.write( getPacketType() );
			outputStream.write( getSeqNo() );
			outputStream.write( getLengthOfPacket() );
			outputStream.write( temp );
			outputStream.write( getIntegrityCheckCode() );
			byte message[] = outputStream.toByteArray( );
			return message;
		}
		else{
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
			byte[] temp=Arrays.copyOfRange(getDataArr(), ctr, ctr+payload);
			outputStream.write( getPacketType() );
			outputStream.write( getSeqNo() );
			outputStream.write( getLengthOfPacket() );
			outputStream.write( temp );
			byte message[] = outputStream.toByteArray( );
			return message;
		}	
	}
	
	public static void main(String[] args) throws Exception{
		int dataCtr=0;//Counter to keep check if all data has been sent
		int timerCounter=1;//Number of timeouts exhausted
		boolean boolCheck = true;//Boolean used to exit loop if correct packet is received
		SecureRandom random = new SecureRandom();//Object random of SecureRandom is created to generate a random stream of data to be sent.
		byte tempCheck[] = new byte[4];
		byte key[] = new byte[]{12,17,78,41,51,90,1,7,8,9,11,13,5,9,1,19};//Defining Key for encryption. 
		byte seqNo[] = new byte[]{14,19,10,55};//Predefined sequence number.
		setSeqNo(seqNo);
		int intSeqNo=ByteBuffer.wrap(seqNo).getInt();
		InetAddress addr = InetAddress.getLocalHost();//Identifying IPAddress of current host.
		DatagramSocket dSocket = new DatagramSocket();
		byte dataCreated[] = new byte[500];//Generating Random Data to be sent
		random.nextBytes(dataCreated);
		setData(dataCreated);
		System.out.print("Sending Data : " + Arrays.toString(dataCreated));
		while(dataCtr<500){
			boolCheck=true;//Resetting boolcheck for next packet.
			//The next if-else statement is used to assign information to "Length of Data", "Packet Type" & "Data Pay Load"
			//fields on the basis of data left to be sent.
			if(500-dataCtr>=30){
				setLengthOfPacket((byte)30);
				setPacketType((byte)0x55);
				dataPayLoad=30;
				
			}
			else{
				setLengthOfPacket((byte)(500-dataCtr));
				setPacketType((byte)0xaa);
				dataPayLoad=500-dataCtr;
			}
			byte[] calcIntegCheck = new byte[dataPayLoad+packetTypeLength+sequenceNumberLength+length];//Byte array used to calculate integrity check field.
			calcIntegCheck = combine(1,dataCtr,dataPayLoad);//Populating the byte array.
			setIntegrityCheckCode(IntegrityCheck.calculateCheck(calcIntegCheck,key));//Calculating integrity check.
			byte[] sendPacket = new byte[dataPayLoad+packetTypeLength+sequenceNumberLength+length+integrityCheckLength];//Byte array to be sent to the server.
			sendPacket=combine(0,dataCtr,dataPayLoad);//Populating the packet to be sent.
			System.out.print("\nPacket Sent :" +Arrays.toString(sendPacket));
			byte[] recPacket = new byte[packetTypeLength+acknowledgementNo+integrityCheckLength];//Byte array to store acknowledgement received from the server.
			DatagramPacket sendMessage = new DatagramPacket(sendPacket, sendPacket.length, addr, 1993);
			DatagramPacket rec = new DatagramPacket(recPacket,recPacket.length,addr,1993);
            dSocket.send(sendMessage);
			while(boolCheck) {
				dSocket.setSoTimeout((int) (Math.pow(2,timerCounter)*timeOutPeriod));
			    try {
			        dSocket.receive(rec);
			        recPacket = rec.getData();//Extract data from received Packet
			        setLengthOfPacket(recPacket[5]);
			        System.out.print("\nPacket Received :" +Arrays.toString(recPacket));
			        tempCheck=Arrays.copyOfRange(recPacket, recPacket.length-4, recPacket.length);//Extracts Integrity check of Acknowledgement Packet
			        byte tempCalc[]=Arrays.copyOfRange(recPacket, 0, recPacket.length-4);//Extracts remaining data and stores it in tempCalc
			        byte calcTemp[]=IntegrityCheck.calculateCheck(tempCalc, key);//Calculates Integrity Check of the packet for cross-verification.
			        System.out.print("\nLocally Calculated Integrity Check : " + Arrays.toString(calcTemp));
			        if (Arrays.equals(calcTemp, tempCheck)){
			        	System.out.print("\nIntegrity Check Matches");
			        	if(recPacket[0]==(byte)0xff){//To check whether it is an acknowledgement packet or not
			        		System.out.print("\nPacket Type Matches");
			        		boolCheck=false;
			        		timerCounter=1;
			        	}
			        	else{
			        		System.out.print("\nPacket Type Mismatch.");
			        		timerCounter=1;//Resets number of timeouts if incorrect packet received
			        		
			        	}
			        }
			        else
			        	System.out.print("\nIntegrity Check Does Not Match!");
			        	timerCounter=1;//Resets number of timeouts
			    } 
			    catch (SocketTimeoutException e) {
			    	if(timerCounter>=4){
			    		//If more than 4 timeouts
			    		System.out.print("\nServer Not Detected. Timeout. Exiting Program!");
			    		System.out.print("\nTimeout Number : " + timerCounter);
				        System.exit(1);
			    	}
			    	else {
			    		System.out.print("\nTimeout Number : " + timerCounter);
			    		System.out.print("\nSending Packet Again");
			    		//Lesser than 4 timeouts. Resends the packet.
			    		dSocket.send(sendMessage);
			    		timerCounter++;
			    		continue;
			    	}
			    }
			}
			//end of while(boolCheck) Loop
			dataCtr=dataCtr+30;
			intSeqNo+=sendPacket[5];//Increments sequence number based on the amount of data sent.
			byte[] newSeqNo = ByteBuffer.allocate(4).putInt(intSeqNo).array();
			setSeqNo(newSeqNo);
		}
		
	}
}