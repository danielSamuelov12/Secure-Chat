package SecureChat;

public class Name {
    private String privateName;
    private String familyName;

    public Name(String privateName, String familyName) {
        this.privateName = privateName;
        this.familyName = familyName;
    }

    public String getPrivateName() {
        return privateName;
    }

    public String getFamilyName() {
        return familyName;
    }
}
