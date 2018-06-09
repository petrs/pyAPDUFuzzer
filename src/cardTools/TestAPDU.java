package cardTools;

import javacard.framework.ISO7816;

class TestAPDU {
    static boolean DISABLE_ALL_FAIL_ON_MATCH = false;   // if true, bFailOnMismatch is overriden

    String dataIn;
    String expectedDataOut;
    int expectedStatus;
    boolean bFailOnMismatch;

    private static final String RESP_OK = "9000";
    
    TestAPDU(String dataIn) {
        this.dataIn = dataIn;
        this.expectedDataOut = "";
        this.bFailOnMismatch = true;
        this.expectedStatus = ISO7816.SW_NO_ERROR & 0xffff;
    }

    TestAPDU(String dataIn, short expectedStatus) {
        this.dataIn = dataIn;
        this.expectedDataOut = "";
        this.bFailOnMismatch = true;
        this.expectedStatus = expectedStatus & 0xffff;
    }

    TestAPDU(String dataIn, String expectedDataOut) {
        this.dataIn = dataIn;
        this.expectedDataOut = expectedDataOut;
        this.bFailOnMismatch = true;
        this.expectedStatus = 0x9000 & 0xffff;
    }

    TestAPDU(String dataIn, String expectedDataOut, boolean bFailOnMismatch) {
        this.dataIn = dataIn;
        this.expectedDataOut = expectedDataOut;
        this.bFailOnMismatch = bFailOnMismatch;
        this.expectedStatus = 0x9000 & 0xffff;
    }
}
