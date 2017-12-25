public class ParamLengths {
    public final int headerLength;
    public final int bodyLength;

    public ParamLengths(int headerLength, int bodyLength) {
        this.headerLength = headerLength;
        this.bodyLength = bodyLength;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        ParamLengths paramLengths = (ParamLengths) o;

        if (headerLength != paramLengths.headerLength) return false;
        return bodyLength == paramLengths.bodyLength;
    }

    @Override
    public int hashCode() {
        int result = headerLength;
        result = 31 * result + bodyLength;
        return result;
    }
}
