package com;

import java.math.BigDecimal;

import static java.math.BigDecimal.ROUND_HALF_UP;

/**
 * @author yangdongpeng
 * @title com.BigDecimalTest
 * @date 2023/8/9 11:23
 * @description TODO
 */
public class BigDecimalTest {


    public static void main(String[] args) {
        BigDecimal big1 = new BigDecimal(Double.valueOf(4515.23)).setScale(2,ROUND_HALF_UP);
        BigDecimal big2 = new BigDecimal(Double.valueOf(100));
        System.out.println(big1.multiply(big2).intValue());//451523
    }

}
