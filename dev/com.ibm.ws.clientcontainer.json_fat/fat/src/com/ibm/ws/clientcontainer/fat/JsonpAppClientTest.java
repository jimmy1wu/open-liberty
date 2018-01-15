/*******************************************************************************
 * Copyright (c) 2015,2018 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *     IBM Corporation - initial API and implementation
 *******************************************************************************/
package com.ibm.ws.clientcontainer.fat;

import java.util.List;

import static org.junit.Assert.assertNotNull;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestName;

import com.ibm.websphere.simplicity.ShrinkHelper;

import componenttest.topology.impl.LibertyClient;
import componenttest.topology.impl.LibertyClientFactory;

public class JsonpAppClientTest {
    private final String testClientName = "com.ibm.ws.clientcontainer.jsonp.fat.ClientContainerClient";
    private final LibertyClient client = LibertyClientFactory.getLibertyClient(testClientName);

    @Rule
    public TestName name = new TestName();

    private void assertClientAppMessage(String msg) {
        assertNotNull("FAIL: Did not receive" + msg + " message", client.waitForStringInCopiedLog(msg));          
    }

	@Test
	public void testJSONPClientAppClient() throws Exception {
        ShrinkHelper.exportToClient(client, "apps", FATSuite.jsonpAppClientApp);

        client.startClient();
        assertClientAppMessage("JSON-P Application Client Completed.");
	}
}
