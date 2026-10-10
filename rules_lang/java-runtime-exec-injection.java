import java.io.IOException;
import javax.servlet.http.HttpServletRequest;

public class Cases {
    private static final String UPTIME = "uptime";

    public void fromRequest(HttpServletRequest request) throws IOException {
        String host = request.getParameter("host");
        // ruleid: codeguard-java-runtime-exec-injection
        Runtime.getRuntime().exec("ping -c 1 " + host);
    }

    public void fromParameter(String userInput) throws IOException {
        // ruleid: codeguard-java-runtime-exec-injection
        Runtime.getRuntime().exec(userInput);
    }

    public void fromHeaderInArray(HttpServletRequest request) throws IOException {
        String file = request.getHeader("X-File");
        // ruleid: codeguard-java-runtime-exec-injection
        Runtime.getRuntime().exec(new String[] {"sh", "-c", "cat " + file});
    }

    public void literal() throws IOException {
        // ok: codeguard-java-runtime-exec-injection
        Runtime.getRuntime().exec("uptime");
    }

    public void constant() throws IOException {
        // ok: codeguard-java-runtime-exec-injection
        Runtime.getRuntime().exec(UPTIME);
    }

    public void numberOnly(int count) throws IOException {
        // ok: codeguard-java-runtime-exec-injection
        Runtime.getRuntime().exec("ping -c " + count + " localhost");
    }

    public void viaVariableIsTheVendoredRules(HttpServletRequest request) throws IOException {
        String host = request.getParameter("host");
        Runtime runtime = Runtime.getRuntime();
        // ok: codeguard-java-runtime-exec-injection
        runtime.exec("ping -c 1 " + host);
    }
}
