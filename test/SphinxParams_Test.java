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
        String iv = "18e3e4c93f5bdd1fb4961630309206e6";
        String key = "5f060d3716b345c253f6749abac10917";
        String expectedOutput = "fbf3df496e16a07c149c197a1772e9901a7fbac16a9424c6282ed06624e4fdec5b2c1c50a347fb782647c8bce5b9a04b32a3eaa1c2d2aae082aad017103aa212e32569a45f0436ff4a5ea95c52522c92";
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