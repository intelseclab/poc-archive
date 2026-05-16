// DISCLAIMER: For authorized security research only.
package com.victim;

import org.apache.avro.generic.GenericRecord;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.Path;
import org.apache.parquet.avro.AvroParquetReader;
import org.apache.parquet.hadoop.ParquetReader;

public class Reader {
    public static void main(String[] args) throws Exception {
        ParquetReader reader = AvroParquetReader.<GenericRecord>builder(new Path("exploit.parquet"))
                .withConf(new Configuration())
                .build();
        reader.read();
        reader.close();
    }
}
