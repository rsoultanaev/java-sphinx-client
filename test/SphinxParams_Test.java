import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;

public class SphinxParams_Test {

    SphinxParams params;

    @Before
    public void setUp() throws Exception {
        params = new SphinxParams();
    }

    @Test
    public void aesCtr() throws Exception {
        String plaintext = "265f3338efbf92c9feacf25fb10778b6d96996e72b41c4e4f55f373d182ba4e1acd5b972e95a917da9f6946924aab6e0b926b94996c25bea7e00422d1f11468578b60f460cb5ce2eafa72fef8cb1a2de";
        String iv = "000000000000000000000000000000";
        String key = "5F060D3716B345C253F6749ABAC10917";
        String expectedOutput = "0e000098e34558b1c728b1580787f881012f2a1eaf3ac383fd596b13d87a95cce1376225b739b15e630f89fe64dbc54752a22ed567f1b368cae6aa1c374fdb008602fbbe5b1cfe3c7c256669e080903d";
        String output = params.aesCtr(plaintext, iv, key);
        assertEquals(expectedOutput, output);
    }

    @Test
    public void hash() throws Exception {
        String plaintext = "265f3338efbf92c9feacf25fb10778b6d96996e72b41c4e4f55f373d182ba4e1acd5b972e95a917da9f6946924aab6e0b926b94996c25bea7e00422d1f11468578b60f460cb5ce2eafa72fef8cb1a2de";
        String expectedOutput = "75cab8f34fc4fed6ad3dd420b1f558a9c55549496316ded97f6bdbf6c5b201e1";
        String output = params.hash(plaintext);
        assertEquals(expectedOutput, output);
    }

}