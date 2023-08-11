package com.example.exe;

import java.math.BigDecimal;
import java.text.NumberFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author yangdongpeng
 * @title testMatches
 * @date 2023/6/1 9:36
 * @description TODO
 */
public class testMatches {

    public static void main(String[] args) {
//        Object o = if.get("1");
//        String dateStr1 = "2022-02-11";
//        String dateStr2 = "2022-02-11 00:00:00";
//
//
//        if (isDateValid(dateStr1) && isDateValid(dateStr2)) {
//            try {
//                SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
//                Calendar cal1 = Calendar.getInstance();
//                Calendar cal2 = Calendar.getInstance();
//                cal1.setTime(dateFormat.parse(dateStr1));
//                cal2.setTime(dateFormat.parse(dateStr2));
//                if (cal1.get(Calendar.YEAR) == cal2.get(Calendar.YEAR) &&
//                        cal1.get(Calendar.MONTH) == cal2.get(Calendar.MONTH) &&
//                        cal1.get(Calendar.DAY_OF_MONTH) == cal2.get(Calendar.DAY_OF_MONTH)) {
//                    System.out.println("日期相同");
//                } else {
//                    System.out.println("日期不同");
//                }
//            } catch (Exception e) {
//                e.printStackTrace();
//            }
//        }
    }

    public static boolean isNumber(String str){

        String reg = "^[0-9]+(.[0-9]+)?$";

        return str.matches(reg);

    }
    private static final String DATE_REGEX = "^\\d{4}-\\d{2}-\\d{2}$|^\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}$";

    public static boolean isDateValid(String date) {
        Pattern pattern = Pattern.compile(DATE_REGEX);
        Matcher matcher = pattern.matcher(date);
        return matcher.matches();
    }
}
