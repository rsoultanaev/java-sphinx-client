public class ParamLens {
    public final int maxLen;
    public final int m;

    public ParamLens(int maxLen, int m) {
        this.maxLen = maxLen;
        this.m = m;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        ParamLens paramLens = (ParamLens) o;

        if (maxLen != paramLens.maxLen) return false;
        return m == paramLens.m;
    }

    @Override
    public int hashCode() {
        int result = maxLen;
        result = 31 * result + m;
        return result;
    }
}
