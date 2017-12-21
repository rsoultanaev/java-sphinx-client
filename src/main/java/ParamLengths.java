public class ParamLengths {
    public final int maxLength;
    public final int bodyLength;

    public ParamLengths(int maxLength, int bodyLength) {
        this.maxLength = maxLength;
        this.bodyLength = bodyLength;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        ParamLengths paramLengths = (ParamLengths) o;

        if (maxLength != paramLengths.maxLength) return false;
        return bodyLength == paramLengths.bodyLength;
    }

    @Override
    public int hashCode() {
        int result = maxLength;
        result = 31 * result + bodyLength;
        return result;
    }
}
