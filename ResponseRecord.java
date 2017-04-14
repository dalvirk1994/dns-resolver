/**
 * Created by Dalvir on 2017-03-06.
 * A class to store record data from a dns response.
 */
public class ResponseRecord {

    private String name;
    private int ttl;
    private int type;
    private String value;

    public ResponseRecord() {
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public void setTtl(int ttl) {
        this.ttl = ttl;
    }

    public int getTtl() {
        return ttl;
    }

    public void setType(int type) {
        this.type = type;
    }

    public int getType() {
        return type;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    public boolean isIPAddress() {
        return type == 1 || type == 28;
    }

    public boolean isIPV6() {
        return type == 28;
    }

    public String getRecordType() {
        String recordType = "";

        switch (type) {
            case 1:
                recordType = "A";
                break;
            case 2:
                recordType = "NS";
                break;
            case 5:
                recordType = "CN";
                break;
            case 28:
                recordType = "AAAA";
                break;
            default:
                recordType = String.valueOf(type);
        }

        return recordType;
    }

    @Override
    public String toString() {
        return String.format("       %-30s %-10d %-4s %s\n", name, ttl, getRecordType(), value);
    }

}
