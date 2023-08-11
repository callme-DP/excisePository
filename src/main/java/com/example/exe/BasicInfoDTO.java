package com.example.exe;

import lombok.Data;

/**
 * @author yangdongpeng
 * @title BasicInfoDTO
 * @date 2023/4/5 22:25
 * @description TODO
 */
@Data
public class BasicInfoDTO {
    private Integer billType;

    public Integer getBillType() {
        return billType;
    }

    public void setBillType(Integer billType) {
        this.billType = billType;
    }

}
