/*******************************************************************************
 * Copyright (c) 2025 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 *******************************************************************************/
package com.ibm.ws.security.utility.tasks;

import java.io.File;
import java.io.PrintStream;

import com.ibm.ws.security.utility.IFileUtility;
import com.ibm.ws.security.utility.SecurityUtilityReturnCodes;
import com.ibm.ws.security.utility.utils.ConsoleWrapper;

/**
 *
 */
public class ConfigureFIPSTask extends BaseCommandTask {

    static final String SLASH = String.valueOf(File.separatorChar);

    static final String DEFAULT_FILE_NAME = "semeruFips140_3CustomProfile.properties";
    static final String ARG_SERVER = "--server";
    static final String ARG_FILE = "--file";
    static final String ARG_RUNTIME = "--runtime";

    static final String PROFILE_NAME = "OpenJCEPlusFIPS.FIPS140-3-Liberty";
    static final String PROFILE = String.join(NL,
                                              "RestrictedSecurity.OpenJCEPlusFIPS.FIPS140-3-Liberty.desc.name = OpenJCEPlusFIPS Cryptographic Module FIPS 140-3 for Liberty",
                                              "RestrictedSecurity.OpenJCEPlusFIPS.FIPS140-3-Liberty.extends = RestrictedSecurity.OpenJCEPlusFIPS.FIPS140-3-JavaStrict",
                                              "RestrictedSecurity.OpenJCEPlusFIPS.FIPS140-3-Liberty.jce.provider.2 = sun.security.provider.Sun [+ \\",
                                              "    {MessageDigest, SHA-1, *, FullClassName:org.objectweb.asm.commons.SerialVersionUIDAdder}, \\",
                                              "    {MessageDigest, SHA-1, *, FullClassName:org.eclipse.persistence.internal.libraries.asm.commons.SerialVersionUIDAdder}, \\",
                                              "    {MessageDigest, SHA-1, *, FullClassName:com.ibm.ws.wsoc.util.Utils}, \\",
                                              "    {MessageDigest, SHA-1, *, FullClassName:com.ibm.ws.collective.security.internal.cert.IBMSignedCertificateCreator}]",
                                              "RestrictedSecurity.OpenJCEPlusFIPS.FIPS140-3-Liberty.jce.provider.4 = com.ibm.ws.collective.security.internal.provider.CollectiveProvider",
                                              "RestrictedSecurity.OpenJCEPlusFIPS.FIPS140-3-Liberty.jce.provider.5 = org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI",
                                              "RestrictedSecurity.OpenJCEPlusFIPS.FIPS140-3-Liberty.jce.provider.6 = org.apache.wss4j.dom.transform.STRTransformProvider");

    protected ConsoleWrapper stdin;
    protected PrintStream stdout;
    protected PrintStream stderr;

    private final IFileUtility fileUtility;

    public ConfigureFIPSTask(IFileUtility fileUtility, String scriptName) {
        super(scriptName);
        this.fileUtility = fileUtility;
    }

    @Override
    public String getTaskName() {
        return "configureFIPS";
    }

    /** {@inheritDoc} */
    @Override
    public String getTaskHelp() {
        return getTaskHelp("configureFIPS.desc", "configureFIPS.usage.options",
                           "configureFIPS.required-key.", "configureFIPS.required-desc.",
                           "configureFIPS.option-key", "configureFIPS.option-desc",
                           null, null, scriptName);
    }

    /** {@inheritDoc} */
    @Override
    public String getTaskDescription() {
        return getOption("configureFIPS.desc", true);
    }

    /** {@inheritDoc} */
    @Override
    public SecurityUtilityReturnCodes handleTask(ConsoleWrapper stdin, PrintStream stdout, PrintStream stderr, String[] args) throws Exception {
        this.stdin = stdin;
        this.stdout = stdout;
        this.stderr = stderr;

        String runtime = getArgumentValue(ARG_RUNTIME, args, "semeru");
        if (runtime.equals("semeru")) {
            return handleSemeruTask(args);
        } else if (runtime.equals("ibmjdk8")) {
            return handleIbmJdk8Task(args);
        } else {
            System.out.println("TODO: unknown runtime");
            return SecurityUtilityReturnCodes.ERR_GENERIC;
        }
    }

    private SecurityUtilityReturnCodes handleSemeruTask(String[] args) {
        String path = getArgumentValue(ARG_FILE, args, System.getProperty("user.dir") + SLASH + DEFAULT_FILE_NAME);
        String serverName = getArgumentValue(ARG_SERVER, args, null);

        if (serverName != null) {
            String usrServers = fileUtility.getServersDirectory();
            String serverDir = usrServers + serverName + SLASH;

            if (!fileUtility.exists(serverDir)) {
                usrServers = fileUtility.resolvePath(usrServers);
                stdout.println(getMessage("configureFIPS.abort"));
                stdout.println(getMessage("serverNotFound", serverName, usrServers));
                return SecurityUtilityReturnCodes.ERR_SERVER_NOT_FOUND;
            }

            // Create the directories we need before we prompt for a password
            String location = serverDir + "resources" + SLASH + "security" + SLASH + DEFAULT_FILE_NAME;
            location = fileUtility.resolvePath(location);
            File fLocation = new File(location);
            if (!fileUtility.createParentDirectory(stdout, fLocation)) {
                stdout.println(getMessage("configureFIPS.abort"));
                stdout.println(getMessage("file.requiredDirNotCreated", location));
                return SecurityUtilityReturnCodes.ERR_PATH_CANNOT_BE_CREATED;
            }

            path = location;
        }

        if (fileUtility.exists(path)) {
            stdout.println(getMessage("configureFIPS.abort"));
            stdout.println(getMessage("configureFIPS.fileExists", path));
            return SecurityUtilityReturnCodes.ERR_FILE_EXISTS;
        } else {
            File customProfileFile = new File(path);
            String jvmOptions = String.join(NL,
                                            "-Dsemeru.fips=true",
                                            "-Dsemeru.customprofile=" + PROFILE_NAME,
                                            "-Djava.security.properties=" + customProfileFile.getAbsolutePath(),
                                            "-Dcom.ibm.ws.beta.edition=true");

            String jvmArgs = String.join(NL,
                                         "# enable_variable_expansion",
                                         "JVM_ARGS=\"" + jvmOptions.replace(NL, " ") + " ${JVM_ARGS}\"");

            fileUtility.writeToFile(stderr, PROFILE, customProfileFile);
            stdout.println(getMessage("configureFIPS.createdFile", path));
            stdout.println(getMessage("configureFIPS.includeJvmOptionsOrArgs", jvmOptions, jvmArgs));
            return SecurityUtilityReturnCodes.OK;
        }
    }

    private SecurityUtilityReturnCodes handleIbmJdk8Task(String[] args) {
        String jvmOptions = String.join(NL,
                                        "-XconfigureFIPS140-3",
                                        "-Dcom.ibm.jsse2.usefipsprovider=true",
                                        "-Dcom.ibm.jsse2.usefipsProviderName=IBMJCEPlusFIPS");

        String jvmArgs = String.join(NL,
                                     "# enable_variable_expansion",
                                     "JVM_ARGS=\"" + jvmOptions.replace(NL, " ") + " ${JVM_ARGS}\"");

        stdout.println(getMessage("configureFIPS.includeJvmOptionsOrArgs", jvmOptions, jvmArgs));
        return SecurityUtilityReturnCodes.OK;
    }

    /** {@inheritDoc} */
    @Override
    boolean isKnownArgument(String arg) {
        return arg.equals(ARG_SERVER)
               || arg.equals(ARG_FILE)
               || arg.equals(ARG_RUNTIME);
    }

    /** {@inheritDoc} */
    @Override
    void checkRequiredArguments(String[] args) throws IllegalArgumentException {
        String message = "";
        // We expect at least the task name
        if (args.length < 1) {
            message = getMessage("insufficientArgs");
        }

        boolean serverFound = false;
        boolean fileFound = false;
        for (String arg : args) {
            String key = arg.split("=")[0];
            if (key.equals(ARG_SERVER)) {
                serverFound = true;
            }
            if (key.equals(ARG_FILE)) {
                fileFound = true;
            }
        }
        if (serverFound && fileFound) {
            //both --server and --file can not be specified
            message += " " + getMessage("exclusiveArg", ARG_SERVER, ARG_FILE);
        }
        if (!message.isEmpty()) {
            throw new IllegalArgumentException(message);
        }
    }

    /**
     * @see BaseCommandTask#getArgumentValue(String, String[], String, String, ConsoleWrapper, PrintStream)
     */
    private String getArgumentValue(String arg, String[] args, String defalt) {
        return getArgumentValue(arg, args, defalt, null, stdin, stdout);
    }

}
