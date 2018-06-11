package cardTools;


import java.io.File;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/**
 *
 * @author Petr Svenda
 */
public class APDUFuzzer {

    
    String getOffsetPrintableName(int position) {
        String nameStr = "";
        return nameStr;
    }

    public void startFuzzing(CardManager cardMngr, RunConfig runCfg, TestCase testCase) throws Exception {
        //
        // Prepare output files
        //
        String experimentID = String.format("%d", System.currentTimeMillis());
        
        String testOutFN = String.format("%s_%s_run.txt", testCase.testName, experimentID);
        File file = new File(testOutFN);
        PrintWriter testOutWriter = new PrintWriter(file);
        String testOutCompactFN = String.format("%s_%s_compactrun.txt", testCase.testName, experimentID);
        File fileCompact = new File(testOutCompactFN);
        PrintWriter testOutWriterCompact = new PrintWriter(fileCompact);
        System.out.println(String.format("Storing fuzzing output into file %s", file.getAbsolutePath()));
        String testOutJSON = String.format("%s_%s_run.json", testCase.testName, experimentID);
        File fileJSON = new File(testOutJSON);
        PrintWriter testOutWriterJSON = new PrintWriter(fileJSON);
        System.out.println(String.format("Storing json output into file %s", fileJSON.getAbsolutePath()));
        testOutWriterJSON.println("{\n");

        testOutWriter.println("########################");
        testOutWriterCompact.println("########################");
        testOutWriter.println(String.format("CaseName = %s", testCase.testName));
        testOutWriterCompact.println(String.format("CaseName = %s", testCase.testName));
        testOutWriter.println(String.format("TemplateValue = %s\n", Util.bytesToHex(testCase.commandTemplate)));
        testOutWriterCompact.println(String.format("TemplateValue = %s\n", Util.bytesToHex(testCase.commandTemplate)));
        testOutWriter.println("########################");
        testOutWriterCompact.println("########################");
        testOutWriter.println("########################");
        testOutWriterCompact.println("########################");
        
        //
        // Run exhaustive fuzzing to modify all bytes
        //
        ArrayList<String> results = new ArrayList<>();
        ArrayList<TestResult> resultsComplete = new ArrayList<>();
        byte[] testCommand = new byte[testCase.commandTemplate.length];
        TestResult testRes = new TestResult();
        int position = testCase.commandTemplateStartChangeOffset; // initial start offset to change commands - start with 0
        for (; position < testCase.commandTemplate.length; position++) {
            int numExceptionsDetected = 0;
            if (testCase.commandTemplateModifMask[position] == 1) { // check if modification for given position is required
                for (int change = 0; change < 256; change++) {
                    testRes.clear();
                    try {
                        if (position == ISO7816.OFFSET_LC) {
                            testCommand = new byte[change + ISO7816.OFFSET_CDATA];
                        }     
                        else {
                            if (testCommand.length != testCase.commandTemplate.length) {
                                testCommand = new byte[testCase.commandTemplate.length];
                            }
                        }
                        
                        // Restore valid input
                        int copyLen = (testCommand.length < testCase.commandTemplate.length) ? testCommand.length : testCase.commandTemplate.length;
                        System.arraycopy(testCase.commandTemplate, 0, testCommand, 0, copyLen);
                        // Make 1B change
                        testCommand[position] = (byte) (change & 0xff);

                        // Reinstall applet if required
                        if (runCfg.bReuploadApplet) {
                            System.out.print("Connecting to card...");
                            if (!cardMngr.Connect(runCfg)) { return;}
                            System.out.println(" Done.");                    
                        }

                        // Send initialization commands sequence
                        if (testCase.initCommands != null) {
                            for (TestAPDU cmd : testCase.initCommands) {
                                cardMngr.m_channel.transmit(new CommandAPDU(Util.hexStringToByteArray(cmd.dataIn)));
                            }
                        }

                        testRes.setInputCmd(testCommand);

                        // Send target fuzzing command
                        System.out.println(String.format("FUZZING: %s", Util.bytesToHex(testCommand)));
                        System.out.println(">>>>");
                        System.out.println(Util.bytesToHex(testCommand));
                        //ResponseAPDU resp = cardMngr.m_channel.transmit(new CommandAPDU(testCommand));
                        ResponseAPDU resp = cardMngr.transmit(new CommandAPDU(testCommand));
                        System.out.println(Util.bytesToHex(resp.getBytes()));

                        // TODO: utilize timing as side-channel information
                        System.out.println(String.format("<<<< Command time: %d ms", cardMngr.m_lastTransmitTime));
                        
                        // If we reach here, no exception was emitted (or is stored in SW)
                        short resCode = (short) resp.getSW();
                        short resCodeOK = (short) ISO7816.SW_NO_ERROR;
                        String msg;
                        if (resCode != resCodeOK) {
                            msg = String.format("ISOException 0x%x (%s)", resp.getSW(), getStatusNameRaw((short) resp.getSW()));
                            numExceptionsDetected++;
                        } else {
                            msg = "OK (no exception)";
                        }
                        testRes.outputData = Util.bytesToHex(resp.getData());
                        testRes.status = resCode;
                        testRes.statusStr = msg;
                        
                        int origValue = testCase.commandTemplate[position] & 0xFF;
                        if (change == origValue) {
                            msg += " @ORIGINAL VALUE";
                        } 
                        System.out.println(String.format(" .. %s", msg));
                        results.add(msg);
                        
                    } catch (ISOException e) {
                        System.out.println(String.format("Command time: %d", cardMngr.m_lastTransmitTime));
                        String msg = String.format("ISOException 0x%x (%s)", e.getReason(), getStatusNameRaw(e.getReason()));
                        results.add(msg);
                        testRes.statusStr = msg;
                        numExceptionsDetected++;
                    } catch (ArrayIndexOutOfBoundsException e) {
                        System.out.println(String.format("Command time: %d", cardMngr.m_lastTransmitTime));
                        String msg = String.format("ArrayIndexOutOfBoundsException");
                        results.add(msg);
                        testRes.statusStr = msg;
                        numExceptionsDetected++;
                    } catch (Exception e) {
                        System.out.println(String.format("Command time: %d", cardMngr.m_lastTransmitTime));
                        String msg = e.toString();
                        results.add(msg);
                        testRes.statusStr = msg;
                        numExceptionsDetected++;
                    }
                    finally {
                        testRes.opTime = cardMngr.m_lastTransmitTime;
                    }
                    
                    resultsComplete.add(testRes);

                    testOutWriterJSON.println(testRes);
                }


                //
                // Process results
                //
                testOutWriter.print(String.format("\nOffset = 0x%02X (%d)", position, position));
                testOutWriterCompact.print(String.format("\nOffset = 0x%02X (%d)", position, position));
                // Annotate offset based on the type of block as extracted from UserObjectOffsets
                String offsetName = getOffsetPrintableName(position);
                if (offsetName.isEmpty()) {
                    testOutWriter.println();
                    testOutWriterCompact.println();
                } else {
                    testOutWriter.println(String.format(" <---- section: %s", offsetName));
                    testOutWriterCompact.println(String.format(" <---- section: %s", offsetName));
                }

                // Printing strategy - try to detected more than 3 subsequent same results.
                // If detected, replace by range print ([37]-[96] OK) instead
                String prevChangeResult = results.get(0);
                int numInRange = 0;
                int firstInRange = 0;
                int MAX_CHANGE_VALUE = 256;
                for (int change = 0; change < MAX_CHANGE_VALUE; change++) {
                    if (results.get(change).compareToIgnoreCase(prevChangeResult) == 0) {
                        // this results is same as previous one - potential range
                        numInRange++;
                    } else {
                        finalizeResultRangePrint(numInRange, firstInRange, change - 1, Integer.MAX_VALUE, results.get(firstInRange), testOutWriter);
                        finalizeResultRangePrint(numInRange, firstInRange, change - 1, 2, results.get(firstInRange), testOutWriterCompact);

                        prevChangeResult = results.get(change);
                        firstInRange = change;
                        numInRange = 1;
                    }
                }
                finalizeResultRangePrint(numInRange, firstInRange, MAX_CHANGE_VALUE - 1, Integer.MAX_VALUE, results.get(firstInRange), testOutWriter);
                finalizeResultRangePrint(numInRange, firstInRange, MAX_CHANGE_VALUE - 1, 2, results.get(firstInRange), testOutWriterCompact);

                results.clear();
            }
        }
        
        testOutWriter.close();
        testOutWriterCompact.close();
        // Finalize JSON file 
        testOutWriterJSON.println("}\n");
        testOutWriterJSON.close();
        Files.copy(new File(testOutFN).toPath(), new File(String.format("%s_run.txt", testCase.testName)).toPath(), StandardCopyOption.REPLACE_EXISTING);
        Files.copy(new File(testOutCompactFN).toPath(), new File(String.format("%s_compactrun.txt", testCase.testName)).toPath(), StandardCopyOption.REPLACE_EXISTING);
        Files.copy(new File(testOutJSON).toPath(), new File(String.format("%s_run.json", testCase.testName)).toPath(), StandardCopyOption.REPLACE_EXISTING);
        
        //
        // Try to find file with baseline results to compare with
        //
/*        
        String testOutBaselineFN = String.format("%s_compactrun_expected.txt", uoName);
        File f = new File(testOutBaselineFN);
        if (f.exists() && !f.isDirectory()) {
            shmLog.trace("I", "1881", "Baseline file detected, going to test for match");

            BufferedReader run = new BufferedReader(new FileReader(testOutCompactFN));
            BufferedReader expected = new BufferedReader(new FileReader(testOutBaselineFN));
            String runLine;
            String expectedLine;
            int lineCounter = 0;
            while ((runLine = run.readLine()) != null) {
                lineCounter++;
                expectedLine = expected.readLine();
                assertNotNull(expectedLine);
                if (runLine.compareTo(expectedLine) != 0) {
                    int a = 0;
                }
                assertEquals(runLine, expectedLine);
            }

            run.close();
            expected.close();
        } else {
            shmLog.trace("I", "1882", "Baseline file NOT detected, omitting test for match");
        }
*/        
    }
    
    private void finalizeResultRangePrint(int numInRange, int firstInRange, int lastInRange, int minValuesInRange, String result, PrintWriter testOutWriter) {
        // Change in result detected - finalize previous values
        if (numInRange < minValuesInRange) {
            // print separately
            for (int x = firstInRange; x <= lastInRange; x++) {
                testOutWriter.println(String.format("  [%02X]\t\t= %s", x, result));
            }
        } else {
            // print as range
            testOutWriter.println(String.format("  [%02X]-[%02X]\t= %s", firstInRange, lastInRange, result));
        }
    }


    public static String getStatusNameRaw(short status) {
/*
    grep Consts.java: short (SW_[A-Z0-9_]*).*=.*\(short\).*(0x[0-9a-fA-F]*)\);
    collect: case Consts.\1: return "\1";
*/
        switch (status) {
            case ISO7816.SW_NO_ERROR:
                return "SW_NO_ERROR";
            case ISO7816.SW_BYTES_REMAINING_00:
                return "SW_BYTES_REMAINING_00";
            case ISO7816.SW_WRONG_LENGTH:
                return "SW_WRONG_LENGTH";
            case ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED:
                return "SW_SECURITY_STATUS_NOT_SATISFIED";
            case ISO7816.SW_FILE_INVALID:
                return "SW_FILE_INVALID";
            case ISO7816.SW_CONDITIONS_NOT_SATISFIED:
                return "SW_CONDITIONS_NOT_SATISFIED";
            case ISO7816.SW_COMMAND_NOT_ALLOWED:
                return "SW_COMMAND_NOT_ALLOWED";
            case ISO7816.SW_APPLET_SELECT_FAILED:
                return "SW_APPLET_SELECT_FAILED";
            case ISO7816.SW_WRONG_DATA:
                return "SW_WRONG_DATA";
            case ISO7816.SW_FUNC_NOT_SUPPORTED:
                return "SW_FUNC_NOT_SUPPORTED";
            case ISO7816.SW_FILE_NOT_FOUND:
                return "SW_FILE_NOT_FOUND";
            case ISO7816.SW_RECORD_NOT_FOUND:
                return "SW_RECORD_NOT_FOUND";
            case ISO7816.SW_INCORRECT_P1P2:
                return "SW_INCORRECT_P1P2";
            case ISO7816.SW_WRONG_P1P2:
                return "SW_WRONG_P1P2";
            case ISO7816.SW_CORRECT_LENGTH_00:
                return "SW_CORRECT_LENGTH_00";
            case ISO7816.SW_INS_NOT_SUPPORTED:
                return "SW_INS_NOT_SUPPORTED";
            case ISO7816.SW_CLA_NOT_SUPPORTED:
                return "SW_CLA_NOT_SUPPORTED";
            case ISO7816.SW_UNKNOWN:
                return "SW_UNKNOWN";
            case ISO7816.SW_FILE_FULL:
                return "SW_FILE_FULL";
            case ISO7816.SW_LOGICAL_CHANNEL_NOT_SUPPORTED:
                return "SW_LOGICAL_CHANNEL_NOT_SUPPORTED";
            case ISO7816.SW_SECURE_MESSAGING_NOT_SUPPORTED:
                return "SW_SECURE_MESSAGING_NOT_SUPPORTED";
            case ISO7816.SW_WARNING_STATE_UNCHANGED:
                return "SW_WARNING_STATE_UNCHANGED";
            case ISO7816.SW_LAST_COMMAND_EXPECTED:
                return "SW_LAST_COMMAND_EXPECTED";
            case ISO7816.SW_COMMAND_CHAINING_NOT_SUPPORTED:
                return "SW_COMMAND_CHAINING_NOT_SUPPORTED";
        }
        
        return "unknown";
    }

}
