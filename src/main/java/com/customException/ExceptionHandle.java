package com.customException;

import com.customException.enumPro.ExceptionEnum;
import com.customException.util.ResultUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;


/**
 * @author yangdongpeng
 * @title ExceptionHandle
 * @date 2023/7/28 15:20
 * @description TODO
 */
@ControllerAdvice
public class ExceptionHandle {

    private final static Logger LOGGER = LoggerFactory.getLogger(ExceptionHandle.class);

    /**
     * 判断错误是否是已定义的已知错误，不是则由未知错误代替，同时记录在log中
     * @param e
     * @return
     */
    @ExceptionHandler(value = Exception.class)
    @ResponseBody
    public Result exceptionGet(Exception e){
        if(e instanceof DescribeException){
            DescribeException MyException = (DescribeException) e;
            return ResultUtil.error(MyException.getCode(),MyException.getMessage());
        }

        LOGGER.error("【系统异常】{}",e);
        return ResultUtil.error(ExceptionEnum.UNKNOW_ERROR);
    }
}
