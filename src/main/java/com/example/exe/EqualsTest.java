package com.example.exe;

/**
 * @author yangdongpeng
 * @title EqualsTest
 * @date 2023/7/28 14:27
 * @description TODO
 */
public class EqualsTest {
    public static void main(String[] args) {
        // 创建两个相同内容的字符串对象
        String str1 = new String("hello");
        String str2 = new String("hello");

        // 比较两个字符串对象的equals()方法和hashCode()方法的返回值
        boolean equalsResult = str1.equals(str2);
        int hashCode1 = str1.hashCode();
        int hashCode2 = str2.hashCode();

        // 输出结果
        System.out.println("equals()结果: " + equalsResult);
        System.out.println("hashCode1: " + hashCode1);
        System.out.println("hashCode2: " + hashCode2);
    }
}
