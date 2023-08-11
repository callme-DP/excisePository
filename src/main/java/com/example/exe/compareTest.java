package com.example.exe;

import org.apache.commons.lang3.StringUtils;

/**
 * @author yangdongpeng
 * @title compareTest
 * @date 2023/4/11 17:08
 * @description TODO
 */
public class compareTest {

    public static void main(String[] args) {
        String str1 = null;
        String str2 = "0.0";
        System.out.println(compareNullOrZero(str1,str2));
        System.out.println("----------------------------------");
        System.out.println( StringUtils.isEmpty(null));
        System.out.println( StringUtils.isEmpty(""));
        System.out.println( StringUtils.isEmpty(" "));
        System.out.println( StringUtils.isEmpty("aaa"));
        System.out.println( StringUtils.isEmpty("\t \n \r \f"));
        System.out.println( StringUtils.isBlank(null));
        System.out.println( StringUtils.isBlank(""));
        System.out.println( StringUtils.isBlank(" "));
        System.out.println( StringUtils.isEmpty("aaa"));
        System.out.println( StringUtils.isEmpty("\t \n \r \f"));










    }


    public static boolean compareNullOrZero(String s1, String s2) {
        if ((s1 == null || "".equals(s1.trim()) || "0".equals(s1.trim()) || "0.0".equals(s1.trim()) || "0.00".equals(s1.trim()))
                && (s2 == null || "".equals(s2.trim()) || "0".equals(s2.trim()) || "0.0".equals(s2.trim()) || "0.00".equals(s2.trim()))
        ) {
            return true;
        } else if (StringUtils.isBlank(s1) && !StringUtils.isBlank(s2)) {
            if (s2.equals(s1)) {
                return true;
            }
        } else if (!StringUtils.isBlank(s1) && StringUtils.isBlank(s2)) {
            if (s1.equals(s2)) {
                return true;
            }
        } else if (StringUtils.isBlank(s1) && StringUtils.isBlank(s2)) {
            return true;
        } else if ((StringUtils.isBlank(s1) || "0".equals(s1) || "0.0".equals(s1) || "0.00".equals(s1))
                && (StringUtils.isBlank(s2) || "0".equals(s2) || "0.0".equals(s2) || "0.00".equals(s2))) {
            return true;
        } else if (s1.equals(s2)) {
            return true;
        }
        return false;
    }
}
