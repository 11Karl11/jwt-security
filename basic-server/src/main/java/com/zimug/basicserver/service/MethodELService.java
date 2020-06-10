package com.zimug.basicserver.service;

import com.zimug.basicserver.model.PersonDemo;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

import static org.springframework.security.core.context.SecurityContextHolder.getContext;

@Service
public class MethodELService {

    @PreAuthorize("hasRole('admin')")
    public List<PersonDemo> findAll(){
        return null;
    }


    @PostAuthorize("returnObject.name == authentication.name")//判断返回值
    public PersonDemo findOne(){
        String authName =
                getContext().getAuthentication().getName();
        System.out.println(authName);
        return new PersonDemo("admin");
    }

    @PreFilter(filterTarget="ids", value="filterObject%2==0")//对参数做过滤,filterTarget过滤的参数,value过滤规则
    public void delete(List<Integer> ids, List<String> usernames) {
        System.out.println();
    }


    @PostFilter("filterObject.name == authentication.name")//对返回值做过滤
    public List<PersonDemo> findAllPD(){

        List<PersonDemo> list = new ArrayList<>();
        list.add(new PersonDemo("kobe"));
        list.add(new PersonDemo("admin"));

        return list;
    }

}
