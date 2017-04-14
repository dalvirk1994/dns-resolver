
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Parses packet responses and allows useful information to be retained.
 */
public class DNSResponse {
    private int queryID;                  // this is for the response it must match the one in the request
    private int answerCount = 0;          // number of answers
    private int nsCount = 0;              // number of nscount response records
    private int additionalCount = 0;      // number of additional (alternate) response records
    private boolean authoritative = false;// Is this an authoritative record
    private byte[] data;
    private List<ResponseRecord> answerList = new ArrayList<>();
    private List<ResponseRecord> nsList = new ArrayList<>();
    private List<ResponseRecord> additionalList = new ArrayList<>();

    /**
     * Print the contents of the dns response.
     */
    void dumpResponse() {
        StringBuilder builder = new StringBuilder();
        builder.append("Response ID: ");
        builder.append(queryID);
        builder.append(" Authoritative ");
        builder.append(authoritative);
        builder.append("\n");
        builder.append("  Answers ");
        builder.append(answerCount);

        builder.append("\n");
        for (ResponseRecord answer : answerList) {
            builder.append(answer.toString());
        }

        builder.append("  Nameservers ");
        builder.append(nsCount);
        builder.append("\n");
        for (ResponseRecord ns : nsList) {
            builder.append(ns.toString());
        }

        builder.append("  Additional Information ");
        builder.append(additionalCount);
        builder.append("\n");
        for (ResponseRecord additional : additionalList) {
            builder.append(additional.toString());
        }

        builder.setLength(builder.length() - 1);
        System.out.println(builder.toString());
    }

    /**
     * Create a DNS Response object.
     *
     * @param data the dns response packet data.
     */
    public DNSResponse(String rootDomainName, byte[] data) throws IOException {
        this.data = data;
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream((data));
        DataInputStream dnsMessage = new DataInputStream(byteArrayInputStream);

        queryID = dnsMessage.readUnsignedShort();

        short placeHolder = dnsMessage.readShort();

        int QR = placeHolder & 0x8000;
        boolean isResponse = QR == 0x8000;

        int OPCODE = placeHolder & 0x7800;

        int AA = placeHolder & 0x0400;
        authoritative = AA == 0x0400;

        int TC = placeHolder & 0x0200;
        int RD = placeHolder & 0x0100;
        int RA = placeHolder & 0x0080;
        int Z = placeHolder & 0x0070;
        int rCode = placeHolder & 0x000F;

        if (rCode != 0) {
            generateError(rootDomainName, rCode);
        }

        int questionCount = dnsMessage.readShort();
        answerCount = dnsMessage.readShort();
        nsCount = dnsMessage.readShort();
        additionalCount = dnsMessage.readShort();

        //skip over question, type, class
        byte length = 1;
        while (length != 0) {
            length = dnsMessage.readByte();
            dnsMessage.skip(length);
        }
        dnsMessage.skip(4);

        for (int i = 0; i < answerCount; i++) {
            answerList.add(getResponseRecord(dnsMessage));
        }

        for (int i = 0; i < nsCount; i++) {
            nsList.add(getResponseRecord(dnsMessage));
        }

        for (int i = 0; i < additionalCount; i++) {
            additionalList.add(getResponseRecord(dnsMessage));
        }
    }

    /**
     * Decode bytes from a dns response message.
     *
     * @param dnsMessage the response dns message.
     * @return the decoded string.
     * @throws IOException
     */
    private String decode(DataInputStream dnsMessage) throws IOException {
        String decodedString = "";
        boolean isTermination = false;
        boolean isFirstCall = true;
        while (!isTermination) {
            dnsMessage.mark(1);
            byte firstByte = dnsMessage.readByte();
            boolean isCompressed = (firstByte & 0xc0) == 0xc0;
            isTermination = firstByte == 0;

            if (!isTermination) {
                dnsMessage.reset();

                if (isFirstCall) {
                    isFirstCall = false;
                } else {
                    decodedString += ".";
                }

                if (isCompressed) {
                    int offset = dnsMessage.readShort() & 0x3FFF;
                    decodedString = decode(decodedString, offset);
                    break;
                } else {
                    byte bytesToRead = dnsMessage.readByte();
                    for (int j = 0; j < bytesToRead; j++) {
                        decodedString += (char) dnsMessage.readByte();
                    }
                }
            }
        }
        return decodedString;
    }

    /**
     * Decode a compressed value within the dns response message.
     *
     * @param decodedString current string that is being decoded.
     * @param offset        the offset to start reading bytes from.
     * @return the decoded string from compression.
     * @throws IOException
     */
    private String decode(String decodedString, int offset) throws IOException {
        byte[] array = Arrays.copyOfRange(data, offset, data.length + 1);
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream((array));
        DataInputStream dnsMessage = new DataInputStream(byteArrayInputStream);

        boolean isTermination = false;
        boolean isFirstCall = true;
        while (!isTermination) {
            dnsMessage.mark(1);
            byte firstByte = dnsMessage.readByte();
            boolean isCompressed = (firstByte & 0xc0) == 0xc0;
            isTermination = firstByte == 0;

            if (!isTermination) {
                dnsMessage.reset();

                if (isFirstCall) {
                    isFirstCall = false;
                } else {
                    decodedString += ".";
                }

                if (isCompressed) {
                    int newOffset = dnsMessage.readShort() & 0x3FFF;
                    decodedString = decode(decodedString, newOffset);
                    break;
                } else {
                    byte bytesToRead = dnsMessage.readByte();
                    for (int j = 0; j < bytesToRead; j++) {
                        decodedString += (char) dnsMessage.readByte();
                    }
                }
            }
        }
        return decodedString;
    }

    /**
     * Create a response record to store record data.
     *
     * @param dnsMessage the response dns message.
     * @return a response record.
     * @throws IOException
     */
    private ResponseRecord getResponseRecord(DataInputStream dnsMessage) throws IOException {
        ResponseRecord responseRecord = new ResponseRecord();

        String name = decode(dnsMessage);


        responseRecord.setName(name);

        int type = dnsMessage.readShort();
        responseRecord.setType(type);

        int rclass = dnsMessage.readShort();

        int ttl = dnsMessage.readInt();
        responseRecord.setTtl(ttl);

        int dataLength = dnsMessage.readShort();

        if (type == 1 || type == 28) {
            byte[] ipAddressBytes = new byte[dataLength];

            for (int k = 0; k < dataLength; k++) {
                ipAddressBytes[k] = dnsMessage.readByte();
            }

            InetAddress ipAddress = InetAddress.getByAddress(ipAddressBytes);
            responseRecord.setValue(ipAddress.getHostAddress());
        } else if (type == 2) {
            String serverName = decode(dnsMessage);
            responseRecord.setValue(serverName);
        } else if (type == 5) {
            String cname = decode(dnsMessage);
            responseRecord.setValue(cname);
        } else {
            dnsMessage.skip(dataLength);
            responseRecord.setValue("----");
        }
        return responseRecord;
    }

    /**
     * Determines the next server to check name (never returns record of type IPV6).
     *
     * @return the response record to use next.
     */
    public ResponseRecord getNextQueryServerRecord() {
        ResponseRecord toUseRecord = null;
        for (ResponseRecord answer : answerList) {
            if (!answer.isIPV6()) {
                toUseRecord = answer;
                break;
            }
        }

        if (toUseRecord == null && !nsList.isEmpty()) {
            toUseRecord = nsList.get(0);

            for (ResponseRecord additional : additionalList) {
                if (toUseRecord.getValue().equals(additional.getName()) && !additional.isIPV6()) {
                    toUseRecord = additional;
                    break;
                }
            }
        }

        if (toUseRecord == null && !additionalList.isEmpty()) {
            for (ResponseRecord additional : additionalList) {
                if (!additional.isIPV6()) {
                    toUseRecord = additional;
                    break;
                }
            }
        }
        return toUseRecord;
    }

    /**
     * Check if rCode produces an error and if so exit.
     *
     * @param rootDomainName - The original name being looked up.
     * @param rCode          - The rcode of the response packet.
     */
    private void generateError(String rootDomainName, int rCode) {
        if (rCode == 3) {
            System.out.println(rootDomainName + " -1   A 0.0.0.0");
        } else {
            System.out.println(rootDomainName + " -4   A 0.0.0.0");
        }
        System.exit(0);
    }

    public int getQueryID() {
        return queryID;
    }

    public boolean isAuthoritative() {
        return authoritative;
    }

    public List<ResponseRecord> getAnswers() {
        return answerList;
    }

}


