import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class QueldaScan {
    /** {@code valid}: exit code 0; {@code json}: the verdict (parse it with your JSON library). */
    record Result(boolean valid, String json) {}

    /** Scans one file with the quelda CLI. Only exit code 0 means valid. */
    static Result scan(String path) throws IOException, InterruptedException {
        Process p = new ProcessBuilder(List.of("quelda", "scan", path))
                .redirectError(ProcessBuilder.Redirect.DISCARD)
                .start();
        CompletableFuture<String> out = CompletableFuture.supplyAsync(() -> {
            try {
                return new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        });
        if (!p.waitFor(30, TimeUnit.SECONDS)) {
            p.destroyForcibly();
            return new Result(false, "{\"status\":\"TIMEOUT\"}");
        }
        return new Result(p.exitValue() == 0, out.join());
    }

    public static void main(String[] args) throws Exception {
        Result r = scan(args[0]);
        Matcher m = Pattern.compile("\"status\":\"(\\w+)\"").matcher(r.json());
        System.out.println("valid=" + r.valid() + " status=" + (m.find() ? m.group(1) : "?"));
    }
}
