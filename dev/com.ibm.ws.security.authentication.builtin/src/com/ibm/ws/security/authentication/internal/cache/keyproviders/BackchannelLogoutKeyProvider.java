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

import java.util.HashSet;
import java.util.Hashtable;
import java.util.Set;

import javax.security.auth.Subject;

import com.ibm.ws.security.authentication.cache.CacheContext;
import com.ibm.ws.security.authentication.cache.CacheKeyProvider;
import com.ibm.ws.security.authentication.utility.SubjectHelper;

/**
 *
 */
public class BackchannelLogoutKeyProvider implements CacheKeyProvider {

    private static final String[] hashtableProperties = { "backchannel-logout-sub" };
    private final SubjectHelper subjectHelper = new SubjectHelper();

    @Override
    public Object provideKey(CacheContext cacheContext) {
        return getBackchannelLogoutKey(cacheContext.getSubject());
    }

    private Set<Object> getBackchannelLogoutKey(final Subject subject) {
        Set<Object> backchannelLogoutKeys = new HashSet<>();
        Hashtable<String, ?> customProperties = subjectHelper.getHashtableFromSubject(subject, hashtableProperties);
        if (customProperties != null) {
            String backchannelLogoutSubKey = (String) customProperties.get("backchannel-logout-sub");
            if (backchannelLogoutSubKey != null && !backchannelLogoutSubKey.isEmpty()) {
                backchannelLogoutKeys.add(backchannelLogoutSubKey);
                customProperties.remove("backchannel-logout-sub");
            }
            String backchannelLogoutSidKey = (String) customProperties.get("backchannel-logout-sid");
            if (backchannelLogoutSidKey != null && !backchannelLogoutSidKey.isEmpty()) {
                backchannelLogoutKeys.add(backchannelLogoutSidKey);
                customProperties.remove("backchannel-logout-sid");
            }
        }
        return backchannelLogoutKeys;
    }

}
