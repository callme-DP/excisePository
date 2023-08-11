package com.customException.com.dp.controller;

import cn.hutool.system.UserInfo;
import com.customException.ExceptionHandle;
import com.customException.Result;
import com.customException.enumPro.ExceptionEnum;
import com.customException.util.ResultUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author yangdongpeng
 * @title ResultController
 * @date 2023/7/28 16:14
 * @description TODO
 */
@RestController
@RequestMapping("/result")
public class ResultController {

    @Autowired
    private ExceptionHandle exceptionHandle;

    /**
     * 返回体测试
     * @param name
     * @param pwd
     * @return
     */
    @RequestMapping(value = "/getResult",method = RequestMethod.POST)
    public Result getResult(@RequestParam("name") String name, @RequestParam("pwd") String pwd){
        Result result = ResultUtil.success();
        try {
            if (name.equals("zzp")){
                result =  ResultUtil.success(new UserInfo());
            }else if (name.equals("pzz")){
                result =  ResultUtil.error(ExceptionEnum.USER_NOT_FIND);
            }else{
                int i = 1/0;
            }
        }catch (Exception e){
            result =  exceptionHandle.exceptionGet(e);
        }
        return result;
    }
}
