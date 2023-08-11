package com.nio;

import org.apache.catalina.mapper.Mapper;
import org.junit.jupiter.api.Test;
import org.springframework.data.mongodb.core.mapping.TextScore;

import javax.xml.stream.events.StartDocument;
import java.io.File;
import java.io.IOException;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

/**
 * @author yangdongpeng
 * @title NIODemo1
 * @date 2023/8/10 16:53
 * @description 文件NIO
 */
public class NIODemo1 {
    @Test
    public void nio1() throws IOException {
        long start = System.currentTimeMillis();
        FileChannel inChannel = FileChannel.open(Paths.get("D:/huohu.png"), StandardOpenOption.READ);
        FileChannel outChannel = FileChannel.open(Paths.get("D:/huohu1.png"), StandardOpenOption.WRITE, StandardOpenOption.READ, StandardOpenOption.CREATE);

        //内存映射文件
        MappedByteBuffer inMapedBuf = inChannel.map(FileChannel.MapMode.READ_ONLY,0,inChannel.size());
        MappedByteBuffer outMapedBuf = outChannel.map(FileChannel.MapMode.READ_WRITE,0,inChannel.size());

        //直接对缓冲区进行数据的读写操作
        byte[] dst = new byte[inMapedBuf.limit()];
//        inMapedBuf.get(dst);
        outMapedBuf.put(dst);

        inChannel.close();
        outChannel.close();
        System.out.println("耗费的时间"+ (System.currentTimeMillis()-start));
    }
}
