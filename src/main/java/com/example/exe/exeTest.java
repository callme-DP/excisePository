package com.example.exe;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import org.apache.commons.collections4.ListUtils;

import java.io.UnsupportedEncodingException;
import java.math.BigDecimal;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.lang3.StringUtils;

/**
 * @author yangdongpeng
 * @title exeTest
 * @date 2023/3/29 17:28
 * @description TODO
 */
public class exeTest {
    public static void main(String[] args) throws UnsupportedEncodingException {
        Integer num = 10;
        for (int i = 0; i < num; i++) {
                if (i == 3){
                    BasicInfoDTO basicInfoDTO = null;
                    if (basicInfoDTO == null){
                        continue;
                    }
                    Integer billType = basicInfoDTO.getBillType();
                }
            System.out.println(i);
        }
    }


    public static boolean isNumber(String s) {
        Pattern pattern = Pattern.compile("^[-+]?[0-9]*\\.?[0-9]+$");
        return pattern.matcher(s).matches();
    }
    public static BasicInfoDTO returntest(){
        if (1==1){
            return null;
        }
        System.out.println("111111111");
        BasicInfoDTO basicInfoDTO = new BasicInfoDTO();
        basicInfoDTO.setBillType(1111111);
        return basicInfoDTO;
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
