package com.white.security.custom;

import java.util.Objects;
import javax.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

public class CustomAuthenticationProvider extends DaoAuthenticationProvider {

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails,
                                                  UsernamePasswordAuthenticationToken authentication)
            throws AuthenticationException {
        //首先获取当前请求，注意这种获取方式，在基于 Spring 的 web 项目中，我们可以随时随地获取到当前请求，获取方式就是我上面给出的代码
        HttpServletRequest req = ((ServletRequestAttributes) Objects.requireNonNull(RequestContextHolder.getRequestAttributes())).getRequest();
        //从当前请求中拿到 code 参数，也就是用户传来的验证码
        String code = req.getParameter("code");
        //从 session 中获取生成的验证码字符串。
        String verify_code = (String) req.getSession().getAttribute("verify_code");
        //两者进行比较，如果验证码输入错误，则直接抛出异常

        //放开下面代码添加验证码校验
//        if (code == null || !code.equals(verify_code)) {
//            throw new AuthenticationServiceException("验证码错误");
//        }

        //最后通过 super 调用父类方法，也就是 DaoAuthenticationProvider 的 additionalAuthenticationChecks 方法，该方法中主要做密码的校验。
        super.additionalAuthenticationChecks(userDetails, authentication);
    }
}