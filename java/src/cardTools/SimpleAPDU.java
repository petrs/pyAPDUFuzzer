package cardTools;

import java.util.ArrayList;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/**
 *
 * @author Petr Svenda
 */
public class SimpleAPDU {
    private final static byte APPLET_AID[] = null;
    private static final String STR_APDU_INS_TEST = "0000000000";
    private static final String STR_APDU_INS_TEST_INS3A = "003a000000";
    private static final String STR_APDU_INS_TEST_INS16 = "0016000000";
    private static final String STR_APDU_INS_TEST_INS16P101 = "0016010000";
    
            
    private static final String MASK_NOMODIF_NONE = "0101010101"; // Allows for modification of any byte
    private static final String MASK_NOMODIF_INSLC = "0100010100"; // Prevents modification of INS and LC
    private static final String MASK_NOMODIF_CLAINSP1 = "0000000101"; // Prevents modification of INS and P1
    private static final String MASK_NOMODIF_CLAINSP1P2 = "0000000001";
    private static final String MASK_NOMODIF_CLAINSLC = "0000010100";
    
            
    public static void main(String[] args) {
        SimpleAPDU tester = new SimpleAPDU();
        tester.run(args);
    }
    
    public void run(String[] args) {
        try {
            runFuzzing();
        } catch (Exception ex) {
            System.out.println("Exception : " + ex);
        }        
    }

    public void runFuzzing() throws Exception {
        CardManager cardMngr = new CardManager(true, APPLET_AID);
        RunConfig runCfg = RunConfig.getDefaultConfig();
        runCfg.testCardType = RunConfig.CARD_TYPE.PHYSICAL;
        runCfg.bReuploadApplet = false;
        runCfg.installData = new byte[8];

        System.out.print("Connecting to card...");
        if (!cardMngr.Connect(runCfg)) {return;}
        System.out.println(" Done.");

        // Prepare fuzzer
        APDUFuzzer fuzzer = new APDUFuzzer();
        // Disable failure on unexpected return status (fuzzing will create many different errors)
        TestAPDU.DISABLE_ALL_FAIL_ON_MATCH = true;
        
        //startFuzzingTemplate(fuzzer, cardMngr, runCfg, "INS_TEST", STR_APDU_INS_TEST, MASK_NOMODIF_NONE, null);
        //startFuzzingTemplate(fuzzer, cardMngr, runCfg, "INS_TEST", STR_APDU_INS_TEST_INS16, MASK_NOMODIF_INSLC, null);
        //startFuzzingTemplate(fuzzer, cardMngr, runCfg, "INS_TEST", STR_APDU_INS_TEST_INS16P101, MASK_NOMODIF_CLAINSP1, null);
        //startFuzzingTemplate(fuzzer, cardMngr, runCfg, "INS_TEST_NOINSLC", STR_APDU_INS_TEST_INS3A, MASK_NOMODIF_INSLC, null);
        
        //startFuzzingTemplate(fuzzer, cardMngr, runCfg, "INS_TEST_NOINSLC", "0bd8104b00", MASK_NOMODIF_CLAINSP1P2, null);
        //startFuzzingTemplate(fuzzer, cardMngr, runCfg, "INS_TEST_NOINSLC", "0bd800000100", MASK_NOMODIF_CLAINSLC, null);
        //startFuzzingTemplate(fuzzer, cardMngr, runCfg, "INS_TEST_NOINSLC", "0be0010000", "0000000001", null);
        //startFuzzingTemplate(fuzzer, cardMngr, runCfg, "INS_TEST_NOINSLC", "0be001001f", "0000000000", null);
        startFuzzingTemplate(fuzzer, cardMngr, runCfg, "INS_TEST_NOINSLC", "0be25b5500", "0000000001", null);
        
    }
    
    static void startFuzzingTemplate(APDUFuzzer fuzzer, CardManager cardMngr, RunConfig runCfg, String testName, String cmdTemplateStr, String cmdTemplateModifMaskStr, ArrayList<TestAPDU> initCommands) throws Exception {
        sendCommandWithInitSequence(cardMngr, cmdTemplateStr, initCommands);

        TestCase testCase = new TestCase(testName);
        if (initCommands != null) {
            testCase.initCommands.addAll(initCommands);
        }
        byte[] cmdTemplate = Util.hexStringToByteArray(cmdTemplateStr);
        testCase.commandTemplate = cmdTemplate;
        byte[] modifMaskTemplate = Util.hexStringToByteArray(cmdTemplateModifMaskStr);
        byte[] modifMask = new byte[cmdTemplate.length];
        for (int i = 0; i < cmdTemplate.length; i++) {
            if (i < modifMaskTemplate.length) {
                modifMask[i] = modifMaskTemplate[i]; // Take modification flag from supplied template
            }
            else {
                modifMask[i] = (byte) 1; // Make modifiable for all non-specified bytes
            }
        }
        testCase.commandTemplateModifMask = modifMask;
        testCase.commandTemplateStartChangeOffset = 0;

        // Run fuzzing
        fuzzer.startFuzzing(cardMngr, runCfg, testCase);
    }    

    static void sendCommand(CardManager cardMngr, TestAPDU cmd) throws CardException, Exception {
        ResponseAPDU resp = cardMngr.m_channel.transmit(new CommandAPDU(Util.hexStringToByteArray(cmd.dataIn)));
        if (!TestAPDU.DISABLE_ALL_FAIL_ON_MATCH && cmd.bFailOnMismatch) {
            if (!cmd.expectedDataOut.isEmpty()) {
                String output = Util.bytesToHex(resp.getBytes());
                if (output.compareToIgnoreCase(cmd.expectedDataOut) != 0) {
                    throw new Exception();
                }
            }
            if (cmd.expectedStatus != (int) (resp.getSW() & 0xffff)) {
                throw new Exception();
            }
        }
    }

    static void sendCommandWithInitSequence(CardManager cardMngr, String command, ArrayList<TestAPDU> initCommands) throws CardException, Exception {
        if (initCommands != null) {
            for (TestAPDU cmd : initCommands) {
                sendCommand(cardMngr, cmd);
            }
        }
        if (!command.isEmpty()) {
            ResponseAPDU resp = cardMngr.m_channel.transmit(new CommandAPDU(Util.hexStringToByteArray(command)));
        }
    }
}
