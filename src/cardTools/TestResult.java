package cardTools;

/**
 *
 * @author Petr Svenda
 */
class TestResult {
    String  inputCmd;
    int   cla;
    int   ins;
    int   p1;
    int   p2;
    int   lc;
    String  inputData;
    
    String  outputData;
    short   status;
    String  statusStr;
    long    opTime;
    
    void setInputCmd(byte[] apdu) {
        cla = apdu[0] & 0xff;
        ins = apdu[1] & 0xff;
        p1 = apdu[2] & 0xff;
        p2 = apdu[3] & 0xff;
        lc = apdu[4] & 0xff;
        inputCmd = Util.bytesToHex(apdu);
        inputData = Util.toHex(apdu, 5, apdu.length - 5); // only data section
    }
    
    
    @Override
    public String toString() {
        return String.format(""
                + "\t{"
                + "cla:%d, "
                + "ins:%d, "
                + "p1:%d, "
                + "p2:%d, "
                + "lc:%d, "
                + "inputData:\"%s\", "
                + "inputCmd:\"%s\", "
                + "outputData:\"%s\", "
                + "status:%d, "
                + "statusStr:\"%s\", "
                + "opTime:%d, "
                + "}", cla, ins, p1, p2, lc, inputData, inputCmd, outputData, status, statusStr, opTime);        
    }
    
    void clear() {
        inputCmd = "";
        cla = 0;
        ins = 0;
        p1 = 0;
        p2 = 0;
        lc = 0;
        inputData = "";
        outputData = "";
        status = 0;
        statusStr = "";
        opTime = 0;        
    }
}
