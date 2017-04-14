
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.util.List;
import java.util.Random;

/**
 * Lookup a fully qualified domain name with a server.
 */
public class DNSlookup {
    private static final int MIN_PERMITTED_ARGUMENT_COUNT = 2;
    private static final int MAX_PERMITTED_ARGUMENT_COUNT = 3;
    private static final int DEFAULT_PORT = 53;
    private static final int RANDOM_GENERATOR_MAX_VALUE = 65535;
    private static final int MAX_SEND_BUF_SIZE = 512;
    private static final int MAX_RECEIVE_BUF_SIZE = 1024;
    private static final int SO_TIMEOUT = 5000;
    private static int QUERY_COUNT = 0;
    private static boolean tracingOn = false;
    private static boolean IPV6Query = false;
    private static final Random randomGenerator = new Random();
    private static String rootDomainName;
    private static DatagramSocket socket;
    private static InetAddress rootServer;

    /**
     * @param args
     */
    public static void main(String[] args) {
        int argCount = args.length;

        if (argCount < MIN_PERMITTED_ARGUMENT_COUNT || argCount > MAX_PERMITTED_ARGUMENT_COUNT) {
            usage();
            return;
        }

        try {
            rootServer = InetAddress.getByName(args[0]);
            rootDomainName = args[1];

            if (argCount == 3) {  // option provided
                if (args[2].equals("-t"))
                    tracingOn = true;
                else if (args[2].equals("-6"))
                    IPV6Query = true;
                else if (args[2].equals("-t6")) {
                    tracingOn = true;
                    IPV6Query = true;
                } else { // option present but wasn't valid option
                    usage();
                    return;
                }
            }
            socket = new DatagramSocket();
            socket.setSoTimeout(SO_TIMEOUT);
            List<ResponseRecord> answerList = sendQuery(rootDomainName, rootServer, IPV6Query);
            if (answerList == null) {
                System.exit(0);
            } else {
                printAnswers(rootDomainName, IPV6Query, answerList);
            }

        } catch (Exception e) {
            System.out.println(rootDomainName + " -4   A 0.0.0.0");
            System.exit(0);
        }

    }

    /**
     * Method to retrieve answers for a lookup.
     *
     * @param fqdn           - The name to be looked up.
     * @param rootNameServer - The server to check against.
     * @param IPV6Lookup     - Flag for ipv6 lookup.
     * @return an answer list.
     * @throws IOException
     */
    static public List<ResponseRecord> sendQuery(String fqdn, InetAddress rootNameServer,
                                                 boolean IPV6Lookup) throws IOException {
        ByteArrayOutputStream dnsMessage = new ByteArrayOutputStream(MAX_SEND_BUF_SIZE);
        DataOutputStream dataOutputStream = new DataOutputStream(dnsMessage);
        DNSResponse response;

        int queryId = randomGenerator.nextInt(RANDOM_GENERATOR_MAX_VALUE + 1);

        QUERY_COUNT++;
        if (QUERY_COUNT > 30) {
            System.out.println(rootDomainName + " -3   A 0.0.0.0");
            return null;
        }

        int SEND_RETRY_COUNTER = 0;
        dataOutputStream.writeShort(queryId);
        // flag identifiers set
        dataOutputStream.writeShort(0x0000);
        // QDCOUNT
        dataOutputStream.writeShort(0x0001);
        // ANCOUNT
        dataOutputStream.writeShort(0x0000);
        // NSCOUNT
        dataOutputStream.writeShort(0x0000);
        // ARCOUNT
        dataOutputStream.writeShort(0x0000);

        // Query Message
        for (final String label : fqdn.split("\\.")) {
            dataOutputStream.writeByte((byte) label.length());
            dataOutputStream.write(label.getBytes());
        }
        // termination byte
        dataOutputStream.writeByte(0x00);
        // QType

        if (IPV6Lookup) {
            dataOutputStream.writeShort(0x001c);
        } else {
            dataOutputStream.writeShort(0x0001);
        }
        // QClass
        dataOutputStream.writeShort(0x0001);

        dataOutputStream.flush();

        while (SEND_RETRY_COUNTER <= 1) {
            if (tracingOn) {
                StringBuilder builder = new StringBuilder();
                builder.append("\n\n");
                builder.append("Query ID     ");
                builder.append(queryId);
                builder.append(" ");
                builder.append(fqdn);
                builder.append("  ");
                if (IPV6Lookup) {
                    builder.append("AAAA");
                } else {
                    builder.append("A");
                }
                builder.append(" --> ");
                builder.append(rootNameServer.getHostAddress());
                System.out.println(builder.toString());
            }

            DatagramPacket sendPacket =
                    new DatagramPacket(dnsMessage.toByteArray(), dnsMessage.size(), rootNameServer, DEFAULT_PORT);
            socket.send(sendPacket);

            try {
                // Wait for response
                DatagramPacket responsePacket =
                        new DatagramPacket(new byte[MAX_RECEIVE_BUF_SIZE], MAX_RECEIVE_BUF_SIZE);
                socket.receive(responsePacket);
                response = new DNSResponse(rootDomainName, responsePacket.getData());

                while (response.getQueryID() != queryId) {
                    responsePacket =
                            new DatagramPacket(new byte[MAX_RECEIVE_BUF_SIZE], MAX_RECEIVE_BUF_SIZE);
                    socket.receive(responsePacket);
                    response = new DNSResponse(rootDomainName, responsePacket.getData());
                }

                if (tracingOn) {
                    response.dumpResponse();
                }

                ResponseRecord record = response.getNextQueryServerRecord();

                if (record == null) {
                    return response.getAnswers();
                }

                if (response.isAuthoritative()) {
                    if (record.getType() == 5) {
                        return sendQuery(record.getValue(), rootServer, IPV6Lookup);
                    }
                    return response.getAnswers();
                } else {
                    if (record.getType() == 5) {
                        return sendQuery(record.getValue(), rootServer, IPV6Lookup);
                    }

                    if (record.getType() == 2) {
                        List<ResponseRecord> answerList =
                                sendQuery(record.getValue(), rootServer, false);
                        if (answerList == null || answerList.isEmpty()) {
                            return answerList;
                        }
                        ResponseRecord answerRecord = answerList.get(0);
                        return sendQuery(fqdn, InetAddress.getByName(answerRecord.getValue()), IPV6Query);
                    }
                    return sendQuery(fqdn, InetAddress.getByName(record.getValue()), IPV6Lookup);
                }
            } catch (SocketTimeoutException ste) {
                SEND_RETRY_COUNTER++;
            }
        }

        System.out.println(rootDomainName + " -2   A 0.0.0.0");
        return null;
    }

    private static void usage() {
        System.out.println("Usage: java -jar DNSlookup.jar rootDNS name [-6|-t|t6]");
        System.out.println("   where");
        System.out.println("       rootDNS - the IP address (in dotted form) of the root");
        System.out.println("                 DNS server you are to start your search at");
        System.out.println("       name    - fully qualified domain name to lookup");
        System.out.println("       -6      - return an IPV6 address");
        System.out.println("       -t      - trace the queries made and responses received");
        System.out.println("       -t6     - trace the queries made, responses received and return an IPV6 address");
    }

    /**
     * A function that prints the answer records.
     *
     * @param fqdn   - the full qualified domain name being looked up.
     * @param isIPv6 - a flag for whether this is a query for ipv6.
     */
    public static void printAnswers(String fqdn, boolean isIPv6, List<ResponseRecord> answerList) {
        boolean hasIPAnswer = false;
        for (ResponseRecord answer : answerList) {

            if (isIPv6) {
                if (answer.isIPV6()) {
                    hasIPAnswer = true;
                    String result = fqdn + " " + answer.getTtl() + "   " + answer.getRecordType()
                            + " " + answer.getValue();
                    System.out.println(result);
                }
            } else if (answer.isIPAddress() && !answer.isIPV6()) {
                hasIPAnswer = true;
                String result = fqdn + " " + answer.getTtl() + "   " + answer.getRecordType()
                        + " " + answer.getValue();
                System.out.println(result);
            }
        }

        if (!hasIPAnswer) {
            System.out.println(fqdn + " -6   A 0.0.0.0");
        }
        System.exit(0);
    }
}


