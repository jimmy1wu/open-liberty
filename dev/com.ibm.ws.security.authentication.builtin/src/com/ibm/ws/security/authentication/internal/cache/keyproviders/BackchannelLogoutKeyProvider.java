/*******************************************************************************
 * Copyright (c) 2023 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 *******************************************************************************/
package com.ibm.ws.security.authentication.internal.cache.keyproviders;

import java.util.Hashtable;

import javax.security.auth.Subject;

import com.ibm.ws.security.authentication.cache.CacheContext;
import com.ibm.ws.security.authentication.cache.CacheKeyProvider;
import com.ibm.ws.security.authentication.utility.SubjectHelper;

/**
 *
 */
public class BackchannelLogoutKeyProvider implements CacheKeyProvider {

    private static final String[] hashtableProperties = { "backchannel-logout" };
    private final SubjectHelper subjectHelper = new SubjectHelper();

    @Override
    public Object provideKey(CacheContext cacheContext) {
        return getBackchannelLogoutKey(cacheContext.getSubject());
    }

    private String getBackchannelLogoutKey(final Subject subject) {
        String backchannelLogoutKey = null;
        Hashtable<String, ?> customProperties = subjectHelper.getHashtableFromSubject(subject, hashtableProperties);
        if (customProperties != null) {
            backchannelLogoutKey = (String) customProperties.get("backchannel-logout");
            if (backchannelLogoutKey != null && !backchannelLogoutKey.isEmpty()) {
                customProperties.remove("backchannel-logout");
            }
        }
        return backchannelLogoutKey;
    }

}
