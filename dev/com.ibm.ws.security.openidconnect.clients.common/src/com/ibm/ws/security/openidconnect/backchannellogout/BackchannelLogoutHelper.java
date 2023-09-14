/*******************************************************************************
 * Copyright (c) 2022 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 *
 * Contributors:
 * IBM Corporation - initial API and implementation
 *******************************************************************************/
package com.ibm.ws.security.openidconnect.backchannellogout;

import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jose4j.jwt.JwtClaims;

import com.ibm.websphere.ras.Tr;
import com.ibm.websphere.ras.TraceComponent;
import com.ibm.ws.ffdc.annotation.FFDCIgnore;
import com.ibm.ws.security.authentication.cache.AuthCacheService;
import com.ibm.ws.security.openidconnect.backchannellogout.internal.LogoutTokenValidator;
import com.ibm.ws.security.openidconnect.clients.common.ConvergedClientConfig;

public class BackchannelLogoutHelper {

    private static TraceComponent tc = Tr.register(BackchannelLogoutHelper.class);

    public static final String LOGOUT_TOKEN_PARAM_NAME = "logout_token";

    private final HttpServletRequest request;
    private final HttpServletResponse response;
    private final ConvergedClientConfig clientConfig;
    private final AuthCacheService authCacheService;

    public BackchannelLogoutHelper(HttpServletRequest request, HttpServletResponse response, ConvergedClientConfig clientConfig, AuthCacheService authCacheService) {
        this.request = request;
        this.response = response;
        this.clientConfig = clientConfig;
        this.authCacheService = authCacheService;
    }

    @FFDCIgnore({ BackchannelLogoutException.class })
    public void handleBackchannelLogoutRequest() {
        try {
            if (clientConfig == null) {
                String errorMsg = Tr.formatMessage(tc, "BACKCHANNEL_LOGOUT_REQUEST_NO_MATCHING_CONFIG");
                throw new BackchannelLogoutException(errorMsg);
            }
            String logoutTokenParameter = validateRequestAndGetLogoutTokenParameter();
            JwtClaims logoutTokenClaims = validateLogoutToken(logoutTokenParameter);
            performLogout(logoutTokenClaims);
            response.setStatus(HttpServletResponse.SC_OK);
        } catch (BackchannelLogoutException e) {
            Tr.error(tc, "BACKCHANNEL_LOGOUT_REQUEST_FAILED", new Object[] { request.getRequestURI(), e.getMessage() });
            response.setStatus(e.getResponseCode());
        }
        response.setHeader("Cache-Control", "no-cache, no-store");
        response.setHeader("Pragma", "no-cache");
    }

    /**
     * Validates:
     * - Server is running in BETA mode
     * - Request uses the HTTP POST method
     * - Request includes a non-empty logout_token parameter
     */
    String validateRequestAndGetLogoutTokenParameter() throws BackchannelLogoutException {
        //        if (!ProductInfo.getBetaEdition()) {
        //            throw new BackchannelLogoutException("BETA: The back-channel logout feature is only available in the beta edition.");
        //        }
        String httpMethod = request.getMethod();
        if (!"POST".equalsIgnoreCase(httpMethod)) {
            throw new BackchannelLogoutException("HTTP " + HttpServletResponse.SC_METHOD_NOT_ALLOWED + " Method Not Allowed (" + httpMethod + ")", HttpServletResponse.SC_METHOD_NOT_ALLOWED);
        }
        String logoutTokenParameter = request.getParameter(LOGOUT_TOKEN_PARAM_NAME);
        if (logoutTokenParameter == null || logoutTokenParameter.isEmpty()) {
            String errorMsg = Tr.formatMessage(tc, "BACKCHANNEL_LOGOUT_REQUEST_MISSING_PARAMETER");
            throw new BackchannelLogoutException(errorMsg);
        }
        return logoutTokenParameter;
    }

    JwtClaims validateLogoutToken(String logoutTokenString) throws BackchannelLogoutException {
        LogoutTokenValidator validator = new LogoutTokenValidator(clientConfig);
        return validator.validateToken(logoutTokenString);
    }

    void performLogout(JwtClaims logoutTokenClaims) throws BackchannelLogoutException {
        try {
            String iss = logoutTokenClaims.getIssuer();
            String sub = logoutTokenClaims.getSubject();
            String sid = logoutTokenClaims.getClaimValue("sid", String.class);
            if (sid != null && !sid.isEmpty()) {
                authCacheService.remove("backchannel-logout-sid:" + iss + ":" + sid);
            } else {
                Set<Object> keys = authCacheService.getAllRelatedKeys("backchannel-logout-sub:" + iss + ":" + sub);
                for (Object key : keys) {
                    authCacheService.remove(key);
                }
                authCacheService.remove("backchannel-logout-sub:" + iss + ":" + sub);
            }
        } catch (Exception e) {
            // should not get here
            // sub and sid claims have been validated and invalidating the session(s) does not throw any errors
            // if we ever get here, we should be returning a status code of 501 as per the backchannel logout spec
        }
    }

}
