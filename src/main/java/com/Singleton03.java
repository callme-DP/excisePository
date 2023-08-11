package com;

/**
 * @author yangdongpeng
 * @title com.Singleton03
 * @date 2023/8/9 15:18
 * @description TODO
 */
public class Singleton03 {
    private static Singleton03 instance;

    private Singleton03() {
    }

    public static Singleton03 getInstance() {
        if (instance == null) {
            synchronized (Singleton03.class) {
                if (instance == null) {
                    instance = new Singleton03();
                }
            }
        }
        return instance;
    }
}
