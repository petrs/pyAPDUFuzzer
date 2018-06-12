package cardTools;

import java.util.ArrayList;

/**
 *
 * @author Petr Svenda
 */
public class TestCase {
    String              testName = "unnamed test";
    ArrayList<TestAPDU>   initCommands = null;
    byte[]              commandTemplate = null;
    byte[]              commandTemplateModifMask = null;
    int                 commandTemplateStartChangeOffset = 0;

    TestCase(String testName) {
        this.testName = testName;
        initCommands = new ArrayList<>();
        commandTemplate = null;
    }
}
