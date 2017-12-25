public class HeaderAndSecrets {
    public final Header header;
    public final byte[][] secrets;

    public HeaderAndSecrets(Header header, byte[][] secrets) {
        this.header = header;
        this.secrets = secrets;
    }
}
