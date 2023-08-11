package com.example.exe;

import java.lang.reflect.Method;

public class ReflectUtil {
    /**
     * 获取对象指定属性的值
     * @param o  对象
     * @param fieldName   要获取值的属性
     * 返回值：对象指定属性的值
     */
    public static Object getFieldValueByName(Object o, String fieldName) {
        try {
            String firstLetter = fieldName.substring(0, 1).toUpperCase();
            String getter = "get" + firstLetter + fieldName.substring(1);
            Method method = o.getClass().getMethod(getter, new Class[] {});
            Object value = method.invoke(o, new Object[] {});
            return value;
        } catch (Exception e) {
            return e;
        }
    }
}
