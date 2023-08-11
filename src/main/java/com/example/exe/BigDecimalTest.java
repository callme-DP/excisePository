package com.example.exe;

import java.math.BigDecimal;

import static java.math.BigDecimal.ZERO;

/**
 * @author yangdongpeng
 * @title com.BigDecimalTest
 * @date 2023/7/25 10:42
 * @description TODO
 */
public class BigDecimalTest {
    public static void main(String[] args) {
        BigDecimal entrySum = new BigDecimal("-0.01");
        BigDecimal approveValue = new BigDecimal("0.05");

        Boolean approveEquation = calculateApproveEquation(entrySum, approveValue).equals(Boolean.TRUE);
        System.out.println(approveEquation?"是":"否");
    }

    public static Boolean calculateApproveEquation(BigDecimal entrySum, BigDecimal approveValue) {
        if (isRuleDefaultValue(entrySum, approveValue)) {
            return true;
        } else if (isErrorValue(entrySum, approveValue)) {
            return false;
        } else if (isDifferenceLessThanThreshold(entrySum, approveValue)) {
            return true;
        } else {
            return false;
        }
    }

    public static boolean isRuleDefaultValue(BigDecimal entrySum, BigDecimal approveValue) {
        return (entrySum == null || ZERO.compareTo(entrySum) == 0) &&
                (approveValue == null || ZERO.compareTo(approveValue) == 0);
    }

    public static boolean isErrorValue(BigDecimal entrySum, BigDecimal approveValue) {
        return (entrySum == null || ZERO.compareTo(entrySum) == 0) ||
                (approveValue == null || ZERO.compareTo(approveValue) == 0);
    }

    public static boolean isDifferenceLessThanThreshold(BigDecimal entrySum, BigDecimal approveValue) {
        BigDecimal difference = entrySum.subtract(approveValue).abs();
        BigDecimal threshold = new BigDecimal("0.05");
        return difference.compareTo(threshold) <= 0;
    }
}
