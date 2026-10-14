// Planted: a request parameter reaches Runtime.exec, via a Runtime variable.
import java.io.IOException;
import javax.servlet.http.HttpServletRequest;

public class Ping {
    public void ping(HttpServletRequest request) throws IOException {
        String host = request.getParameter("host");
        Runtime runtime = Runtime.getRuntime();
        runtime.exec("ping -c 1 " + host);
    }
}
