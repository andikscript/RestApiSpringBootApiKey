package com.andikscript.tokosepatu.security;

import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;

// class yang berfungsi untuk menangkap header dari request client
public class APIKeyAuthFilter extends AbstractPreAuthenticatedProcessingFilter {

    private String principalRequestHeader;

    public APIKeyAuthFilter(String principalRequestHeader) {
        this.principalRequestHeader = principalRequestHeader;
    }

    @Override
    protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
        return request.getHeader(principalRequestHeader);
    }

    @Override
    protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
        return "N/A";
    }
}
