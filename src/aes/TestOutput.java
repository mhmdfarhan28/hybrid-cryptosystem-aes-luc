package aes;

public class TestOutput {
    private long textsize,aes_enctime,luc_enctime,aesluc_enctime,aes_dectime,luc_dectime,aesluc_dectime;

    public TestOutput(long textsize,long aes_enctime,long luc_enctime,long aesluc_enctime,long aes_dectime,long luc_dectime,long aesluc_dectime){
        this.textsize=textsize;
        this.aes_enctime=aes_enctime;
        this.luc_enctime=luc_enctime;
        this.aesluc_enctime=aesluc_enctime;
        this.aes_dectime=aes_dectime;
        this.luc_dectime=luc_dectime;
        this.aesluc_dectime=aesluc_dectime;
    }

    public long getTextsize() {
        return textsize;
    }

    public long getAes_enctime() {
        return aes_enctime;
    }

    public long getLuc_enctime() {
        return luc_enctime;
    }

    public long getAesluc_enctime() {
        return aesluc_enctime;
    }

    public long getAes_dectime() {
        return aes_dectime;
    }

    public long getLuc_dectime() {
        return luc_dectime;
    }

    public long getAesluc_dectime() {
        return aesluc_dectime;
    }

}
