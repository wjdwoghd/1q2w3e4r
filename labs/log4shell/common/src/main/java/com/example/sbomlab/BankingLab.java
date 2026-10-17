package com.example.sbomlab;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.LoggerContext;

/** Isolated synthetic service; only fixed messages are sent to the vulnerable logger. */
public final class BankingLab {
    private static final String HEALTH = "{\"status\":\"ok\"}";
    private static final String SMOKE = "{\"result\":\"ok\",\"mode\":\"synthetic\"}";
    private static final Logger LOGGER = LogManager.getLogger(BankingLab.class);

    private BankingLab() { }

    public static void main(String[] args) throws Exception {
        if (args.length == 1 && args[0].equals("--self-test")) {
            if (!SMOKE.equals(runSyntheticBankingCheck())) {
                throw new IllegalStateException("synthetic business check failed");
            }
            System.out.println(runtimeInventory());
            return;
        }
        if (args.length == 1 && args[0].equals("--healthcheck")) {
            checkHealth();
            return;
        }
        String host = "127.0.0.1";
        int port = 8080;
        for (int index = 0; index < args.length; index += 2) {
            if (index + 1 >= args.length) {
                throw new IllegalArgumentException("expected --host ADDRESS or --port NUMBER");
            }
            switch (args[index]) {
                case "--host" -> host = args[index + 1];
                case "--port" -> port = Integer.parseInt(args[index + 1]);
                default -> throw new IllegalArgumentException("unsupported option");
            }
        }
        if (port < 0 || port > 65535) {
            throw new IllegalArgumentException("port out of range");
        }
        InetAddress address = InetAddress.getByName(host);
        // Container builds opt in; direct host use always remains on loopback.
        if (!address.isLoopbackAddress()
                && !(host.equals("0.0.0.0") && "1".equals(System.getenv("LAB_CONTAINER")))) {
            throw new IllegalArgumentException("host execution requires a loopback address");
        }
        HttpServer server = HttpServer.create(new InetSocketAddress(address, port), 16);
        ExecutorService executor = Executors.newFixedThreadPool(4);
        server.setExecutor(executor);
        server.createContext("/", BankingLab::handle);
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            server.stop(0);
            executor.shutdownNow();
            LogManager.shutdown();
        }));
        server.start();
        System.out.println("{\"host\":\"" + host + "\",\"port\":" + server.getAddress().getPort() + "}");
        System.out.flush();
    }

    private static void handle(HttpExchange exchange) throws IOException {
        try {
            if (!exchange.getRequestMethod().equals("GET")) {
                exchange.getResponseHeaders().set("Allow", "GET");
                respond(exchange, 405, "{\"error\":\"method_not_allowed\"}");
                return;
            }
            String path = exchange.getRequestURI().getPath();
            switch (path) {
                case "/health" -> respond(exchange, 200, HEALTH);
                case "/banking/smoke" -> respond(exchange, 200, runSyntheticBankingCheck());
                case "/runtime" -> respond(exchange, 200, runtimeInventory());
                default -> respond(exchange, 404, "{\"error\":\"not_found\"}");
            }
        } finally {
            exchange.close();
        }
    }

    private static String runSyntheticBankingCheck() {
        // No headers, request parameters, account data or user-controlled strings enter Log4j.
        LOGGER.info("Synthetic banking check completed");
        return SMOKE;
    }

    private static String runtimeInventory() {
        return "{\"log4j_api_version\":" + versionJson(LogManager.class)
                + ",\"log4j_core_version\":" + versionJson(LoggerContext.class) + "}";
    }

    private static String versionJson(Class<?> type) {
        String version = type.getPackage().getImplementationVersion();
        // Report missing metadata honestly instead of echoing the configured POM version.
        return version == null ? "null" : "\"" + version.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    private static void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.getResponseHeaders().set("Cache-Control", "no-store");
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
    }

    private static void checkHealth() throws Exception {
        HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();
        HttpRequest request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:8080/health"))
                .timeout(Duration.ofSeconds(3)).GET().build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200 || !response.body().equals(HEALTH)) {
            throw new IllegalStateException("health contract failed");
        }
    }
}
