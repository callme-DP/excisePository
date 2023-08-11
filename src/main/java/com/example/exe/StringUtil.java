package com.example.exe;

import cn.hutool.core.util.NumberUtil;

import java.io.UnsupportedEncodingException;
import java.math.BigDecimal;
import java.net.URLEncoder;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class StringUtil {
    private static final String[] hex = new String[]{"00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "0A", "0B", "0C", "0D", "0E", "0F", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "1A", "1B", "1C", "1D", "1E", "1F", "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "2A", "2B", "2C", "2D", "2E", "2F", "30", "31", "32", "33", "34", "35", "36", "37", "38", "39", "3A", "3B", "3C", "3D", "3E", "3F", "40", "41", "42", "43", "44", "45", "46", "47", "48", "49", "4A", "4B", "4C", "4D", "4E", "4F", "50", "51", "52", "53", "54", "55", "56", "57", "58", "59", "5A", "5B", "5C", "5D", "5E", "5F", "60", "61", "62", "63", "64", "65", "66", "67", "68", "69", "6A", "6B", "6C", "6D", "6E", "6F", "70", "71", "72", "73", "74", "75", "76", "77", "78", "79", "7A", "7B", "7C", "7D", "7E", "7F", "80", "81", "82", "83", "84", "85", "86", "87", "88", "89", "8A", "8B", "8C", "8D", "8E", "8F", "90", "91", "92", "93", "94", "95", "96", "97", "98", "99", "9A", "9B", "9C", "9D", "9E", "9F", "A0", "A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A9", "AA", "AB", "AC", "AD", "AE", "AF", "B0", "B1", "B2", "B3", "B4", "B5", "B6", "B7", "B8", "B9", "BA", "BB", "BC", "BD", "BE", "BF", "C0", "C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "CA", "CB", "CC", "CD", "CE", "CF", "D0", "D1", "D2", "D3", "D4", "D5", "D6", "D7", "D8", "D9", "DA", "DB", "DC", "DD", "DE", "DF", "E0", "E1", "E2", "E3", "E4", "E5", "E6", "E7", "E8", "E9", "EA", "EB", "EC", "ED", "EE", "EF", "F0", "F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8", "F9", "FA", "FB", "FC", "FD", "FE", "FF"};
    private static final byte[] val = new byte[]{63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 63, 63, 63, 63, 63, 63, 63, 10, 11, 12, 13, 14, 15, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 10, 11, 12, 13, 14, 15, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63};
    private static char[] HEXCHAR = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    public StringUtil() {
    }

    public static String toHexString(byte[] b) {
        StringBuffer sb = new StringBuffer(b.length * 2);

        for(int i = 0; i < b.length; ++i) {
            sb.append(HEXCHAR[(b[i] & 240) >>> 4]);
            sb.append(HEXCHAR[b[i] & 15]);
        }

        return sb.toString();
    }

    public static final byte[] toBytes(String s) {
        byte[] bytes = new byte[s.length() / 2];

        for(int i = 0; i < bytes.length; ++i) {
            bytes[i] = (byte)Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        }

        return bytes;
    }

    public static String escape(String sourceStr) {
        StringBuffer sbuf = new StringBuffer();
        int len = sourceStr.length();

        for(int i = 0; i < len; ++i) {
            int ch = sourceStr.charAt(i);
            if ('A' <= ch && ch <= 'Z') {
                sbuf.append((char)ch);
            } else if ('a' <= ch && ch <= 'z') {
                sbuf.append((char)ch);
            } else if ('0' <= ch && ch <= '9') {
                sbuf.append((char)ch);
            } else if (ch != '-' && ch != '_' && ch != '.' && ch != '!' && ch != '~' && ch != '*' && ch != '\'' && ch != '(' && ch != ')') {
                if (ch <= 127) {
                    sbuf.append('%');
                    sbuf.append(hex[ch]);
                } else if (ch == ' ') {
                    sbuf.append("%20");
                } else {
                    sbuf.append('%');
                    sbuf.append('u');
                    sbuf.append(hex[ch >>> 8]);
                    sbuf.append(hex[255 & ch]);
                }
            } else {
                sbuf.append((char)ch);
            }
        }

        return sbuf.toString();
    }

    public static String unescape(String sourceStr) {
        StringBuffer sbuf = new StringBuffer();
        int i = 0;

        for(int len = sourceStr.length(); i < len; ++i) {
            int ch = sourceStr.charAt(i);
            if ('A' <= ch && ch <= 'Z') {
                sbuf.append((char)ch);
            } else if ('a' <= ch && ch <= 'z') {
                sbuf.append((char)ch);
            } else if ('0' <= ch && ch <= '9') {
                sbuf.append((char)ch);
            } else if (ch != '-' && ch != '_' && ch != '.' && ch != '!' && ch != '~' && ch != '*' && ch != '\'' && ch != '(' && ch != ')') {
                if (ch == '%') {
                    int cint = 0;
                    if ('u' != sourceStr.charAt(i + 1)) {
                        cint = cint << 4 | val[sourceStr.charAt(i + 1)];
                        cint = cint << 4 | val[sourceStr.charAt(i + 2)];
                        i += 2;
                    } else {
                        cint = cint << 4 | val[sourceStr.charAt(i + 2)];
                        cint = cint << 4 | val[sourceStr.charAt(i + 3)];
                        cint = cint << 4 | val[sourceStr.charAt(i + 4)];
                        cint = cint << 4 | val[sourceStr.charAt(i + 5)];
                        i += 5;
                    }

                    sbuf.append((char)cint);
                } else {
                    sbuf.append((char)ch);
                }
            } else {
                sbuf.append((char)ch);
            }
        }

        return sbuf.toString();
    }

    public static String XMLEscape(String src) {
        if (src == null) {
            return null;
        } else {
            String rtnVal = src.replaceAll("&", "&amp;");
            rtnVal = rtnVal.replaceAll("\"", "&quot;");
            rtnVal = rtnVal.replaceAll("<", "&lt;");
            rtnVal = rtnVal.replaceAll(">", "&gt;");
            rtnVal = rtnVal.replaceAll("[\\x00-\\x08\\x0b-\\x0c\\x0e-\\x1f]", "");
            return rtnVal;
        }
    }

    public static String getParameter(String query, String param) {
        Pattern p = Pattern.compile("&" + param + "=([^&]*)");
        Matcher m = p.matcher("&" + query);
        return m.find() ? m.group(1) : null;
    }

    public static Map getParameterMap(String query, String splitStr) {
        Map rtnVal = new HashMap();
        if (isNull(query)) {
            return rtnVal;
        } else {
            String[] parameters = query.split("\\s*" + splitStr + "\\s*");

            for(int i = 0; i < parameters.length; ++i) {
                int j = parameters[i].indexOf(61);
                if (j > -1) {
                    rtnVal.put(parameters[i].substring(0, j), new String[]{parameters[i].substring(j + 1)});
                }
            }

            return rtnVal;
        }
    }

    public static String setQueryParameter(String query, String param, String value) {
        String rtnVal = null;

        try {
            String m_query = isNull(query) ? "" : "&" + query;
            String m_param = "&" + param + "=";
            String m_value = URLEncoder.encode(value, "UTF-8");
            Pattern p = Pattern.compile(m_param + "[^&]*");
            Matcher m = p.matcher(m_query);
            if (m.find()) {
                rtnVal = m.replaceFirst(m_param + m_value);
            } else {
                rtnVal = m_query + m_param + m_value;
            }

            rtnVal = rtnVal.substring(1);
        } catch (UnsupportedEncodingException var9) {
            var9.printStackTrace();
        }

        return rtnVal;
    }

    public static String replace(String srcText, String fromStr, String toStr) {
        if (srcText == null) {
            return null;
        } else {
            StringBuffer rtnVal = new StringBuffer();
            String rightText = srcText;

            for(int i = srcText.indexOf(fromStr); i > -1; i = rightText.indexOf(fromStr)) {
                rtnVal.append(rightText.substring(0, i));
                rtnVal.append(toStr);
                rightText = rightText.substring(i + fromStr.length());
            }

            rtnVal.append(rightText);
            return rtnVal.toString();
        }
    }

    public static String format(String str, int max) {
        if(StringUtil.isNotNull(str)){
            if(str.length()<max){
                str="0"+str;
            }
        }

       return str;
    }
    public static String formatUrl(String url, String urlPrefix) {
        return !url.startsWith("/") ? url : urlPrefix + url;
    }

    public static String linkString(String leftStr, String linkStr, String rightStr) {
        if (isNull(leftStr)) {
            return rightStr;
        } else {
            return isNull(rightStr) ? leftStr : leftStr + linkStr + rightStr;
        }
    }

    public static boolean isNull(String str) {
        return str == null || str.trim().length() == 0;
    }

    public static boolean isNotNull(String str) {
        return !isNull(str);
    }

    public static boolean hasLength(String str) {
        return str != null && str.length() > 0;
    }

    public static String getString(String s) {
        return s == null ? "" : (s.equals("null") ? "" : s);
    }

    public static String linkPathString(String... paths) {
        if (null != paths && paths.length != 0) {
            StringBuilder sb = new StringBuilder();
            sb.append(paths[0]);

            for(int i = 1; i < paths.length; ++i) {
                if (!paths[i - 1].endsWith("\\") && !paths[i - 1].endsWith("/")) {
                    if (!paths[i].startsWith("\\") && !paths[i].startsWith("/")) {
                        sb.append("/").append(paths[i]);
                    } else {
                        sb.append(paths[i]);
                    }
                } else if (!paths[i].startsWith("\\") && !paths[i].startsWith("/")) {
                    sb.append(paths[i]);
                } else {
                    sb.append(paths[i].substring(1));
                }
            }

            return sb.toString();
        } else {
            return "";
        }
    }

    public static int getIntFromString(String value, int defaultValue) {
        int ret = defaultValue;
        if (isNotNull(value)) {
            try {
                ret = Integer.parseInt(value);
            } catch (NumberFormatException var4) {
                ret = defaultValue;
            }
        }

        return ret;
    }

    public static String[] mergeStringArray(String[] ary1, String[] ary2) {
        if (null == ary1) {
            return ary2;
        } else if (null == ary2) {
            return ary1;
        } else {
            List<String> l1 = new ArrayList(Arrays.asList(ary1));
            List<String> l2 = Arrays.asList(ary2);
            Iterator var4 = l2.iterator();

            while(var4.hasNext()) {
                String s = (String)var4.next();
                if (!l1.contains(s)) {
                    l1.add(s);
                }
            }

            String[] strings = new String[l1.size()];
            l1.toArray(strings);
            return strings;
        }
    }

    public static String[] emptyArray2Null(String[] ary1) {
        return null != ary1 && ary1.length != 0 ? ary1 : null;
    }

    public static String clearScriptTag(String html) {
        Pattern scriptTag = Pattern.compile("<script[^>]*>.*(?=<\\/script>)<\\/script>");
        Matcher mTag = scriptTag.matcher(html);
        html = mTag.replaceAll("");
        String regx = "(<[^<]*)(on\\w*\\x20*=|javascript:)";
        Pattern pattern = Pattern.compile(regx, 10);

        Matcher matcher;
        String ts;
        for(ts = html; (matcher = pattern.matcher(ts)).find(); ts = matcher.replaceAll("$1_disibledevent=")) {
        }

        return ts;
    }

    public static String join(String[] array, String separator) {
        if (array == null) {
            return null;
        } else {
            if (separator == null) {
                separator = "";
            }

            StringBuffer buf = new StringBuffer();

            for(int i = 0; i < array.length; ++i) {
                if (i > 0) {
                    buf.append(separator);
                }

                if (array[i] != null) {
                    buf.append(array[i]);
                }
            }

            return buf.toString();
        }
    }

    public static String join(Iterable iterable, String separator) {
        return iterable == null ? null : join(iterable.iterator(), separator);
    }

    public static String join(Iterator iterator, String separator) {
        if (iterator == null) {
            return null;
        } else if (!iterator.hasNext()) {
            return "";
        } else {
            Object first = iterator.next();
            if (!iterator.hasNext()) {
                return first == null ? "" : first.toString();
            } else {
                StringBuffer buf = new StringBuffer(256);
                if (first != null) {
                    buf.append(first);
                }

                while(iterator.hasNext()) {
                    if (separator != null) {
                        buf.append(separator);
                    }

                    Object obj = iterator.next();
                    if (obj != null) {
                        buf.append(obj);
                    }
                }

                return buf.toString();
            }
        }
    }

    public static boolean equal(String s1, String s2) {
        if (s1 == null && s2 == null) {
            return true;
        } else if (s1 != null && s2 != null) {
            return s1.isEmpty() && s2.isEmpty() ? true : s1.equals(s2);
        } else {
            return false;
        }
    }

    public static boolean inArray(String[] array, String value) {
        if (array != null) {
            for(int i = 0; i < array.length; ++i) {
                if (equal(array[i], value)) {
                    return true;
                }
            }
        }

        return false;
    }

    public static String uriEncode(String url) {
        try {
            int index = url.lastIndexOf("/");
            return index >= 0 && index < url.length() - 1 ? url.substring(0, index + 1) + URLEncoder.encode(url.substring(index + 1), "UTF-8") : url;
        } catch (Exception var2) {
            var2.printStackTrace();
            return url;
        }
    }

    private static boolean checkTimeFormat(String validateDate) {
        Pattern pattern = Pattern
                .compile("^((\\d{2}(([02468][048])|([13579][26]))[\\-\\/\\s]?((((0?[13578])|(1[02]))[\\-\\/\\s]?((0?[1-9])|([1-2][0-9])|(3[01])))|(((0?[469])|(11))[\\-\\/\\s]?((0?[1-9])|([1-2][0-9])|(30)))|(0?2[\\-\\/\\s]?((0?[1-9])|([1-2][0-9])))))|(\\d{2}(([02468][1235679])|([13579][01345789]))[\\-\\/\\s]?((((0?[13578])|(1[02]))[\\-\\/\\s]?((0?[1-9])|([1-2][0-9])|(3[01])))|(((0?[469])|(11))[\\-\\/\\s]?((0?[1-9])|([1-2][0-9])|(30)))|(0?2[\\-\\/\\s]?((0?[1-9])|(1[0-9])|(2[0-8]))))))(\\s(((0?[0-9])|([1-2][0-3]))\\:([0-5]?[0-9])((\\s)|(\\:([0-5]?[0-9])))))?$");
        Matcher matcher = pattern.matcher(validateDate);
        if (matcher.matches()) {
            return true;
        } else {
            return false;
        }

    }
    public static String parseString(Object param)  {
        if(param == null){
            return "";
        }
        if(param instanceof String ){
            String num = (String)param;
            if(NumberUtil.isNumber(num) && num.length() <10){
                BigDecimal bigDecimal = new BigDecimal(num).stripTrailingZeros();
                return bigDecimal.toPlainString();
            }else if(checkTimeFormat(num)){
                return num.substring(0,10);
            } else{
                return num;
            }
        }else if (param instanceof Date) {
            String format = "";
            try {
                Date d = (Date) param;
                SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd");
                format = formatter.format(d);
                Date parse = formatter.parse(format);
                String zz = formatter.format(parse);

            }catch (Exception e){
                e.printStackTrace();
            }
            return format;

        }else if (param instanceof BigDecimal) {
            BigDecimal bigDecimal = ((BigDecimal) param).stripTrailingZeros();
            return bigDecimal.toPlainString();
        }else if (param instanceof Double) {
            BigDecimal bigDecimal = (BigDecimal.valueOf((Double)param)).stripTrailingZeros();
            return bigDecimal.toPlainString();
        }else {
            return String.valueOf(param);
        }

    }
}