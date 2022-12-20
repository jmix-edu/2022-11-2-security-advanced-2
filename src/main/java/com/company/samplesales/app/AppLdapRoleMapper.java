package com.company.samplesales.app;

import com.company.samplesales.security.FullAccessRole;
import com.company.samplesales.security.ReaderRole;
import com.company.samplesales.security.SellerRole;
import com.google.common.collect.ImmutableMap;
import io.jmix.ldap.userdetails.LdapAuthorityToJmixRoleCodesMapper;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;

@Component("sales_AppLdapRoleMapper")
public class AppLdapRoleMapper implements LdapAuthorityToJmixRoleCodesMapper {

    private final static Map<String, String> roleCodes = ImmutableMap.of(
            "admin", FullAccessRole.CODE,
            "developers", ReaderRole.CODE,
            "managers", SellerRole.CODE
    );

    @Override
    public Collection<String> mapAuthorityToJmixRoleCodes(String authority) {
        return Collections.singletonList(roleCodes.getOrDefault(authority, authority));
    }
}
