package com.ljx.domain;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

/**
 * @author 李加喜
 * @date 2020/11/24 0024 16:11
 * @Email 1129071273@qq.com
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@Accessors(chain = true)
public class Users {
    private Integer id;
    private String username;
    private String password;
}
