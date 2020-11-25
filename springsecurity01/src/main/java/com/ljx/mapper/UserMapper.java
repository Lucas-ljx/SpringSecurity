package com.ljx.mapper;

import com.baomidou.mybatisplus.core.conditions.Wrapper;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.baomidou.mybatisplus.core.metadata.IPage;
import com.ljx.domain.Users;
import org.springframework.stereotype.Repository;

import java.io.Serializable;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * @author 李加喜
 * @date 2020/11/24 0024 16:16
 * @Email 1129071273@qq.com
 */
@Repository
public interface UserMapper extends BaseMapper<Users> {

}
