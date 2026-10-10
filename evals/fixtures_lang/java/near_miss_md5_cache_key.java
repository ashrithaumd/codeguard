// Near miss: MD5, but as a cache key for public content, not for security.
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

public class CacheKeys {
    public static String forUrl(String publicUrl) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return HexFormat.of().formatHex(md.digest(publicUrl.getBytes(StandardCharsets.UTF_8)));
    }
}
