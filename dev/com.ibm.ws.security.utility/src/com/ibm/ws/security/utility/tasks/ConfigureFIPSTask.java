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
import java.io.IOException;
import java.io.PrintStream;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.apache.commons.io.FilenameUtils;

import com.ibm.ws.kernel.productinfo.ProductInfo;
import com.ibm.ws.security.utility.IFileUtility;
import com.ibm.ws.security.utility.SecurityUtilityReturnCodes;
import com.ibm.ws.security.utility.utils.ConsoleWrapper;

/**
 *
 */
public class ConfigureFIPSTask extends BaseCommandTask {

    static final String SLASH = String.valueOf(File.separatorChar);
    static final String PATH_SEPARATOR = File.pathSeparator;

    static final String ARG_SERVER = "--server";
    static final String ARG_CLIENT = "--client";
    static final String ARG_DISABLE = "--disable";
    static final String ARG_CUSTOMPROFILE_FILE = "--customProfileFile";

    static final String DEFAULT_ENV = "default.env";
    static final String SERVER_ENV = "server.env";
    static final String CLIENT_ENV = "client.env";
    static final String ENABLE_FIPS140_3_ENV_VAR = "ENABLE_FIPS140_3";

    static final String LIBERTY_PROFILE_FILE_NAME = "FIPS140-3-Liberty.properties";
    static final String APP_PROFILE_FILE_NAME = "FIPS140-3-Liberty-Application.properties";

    static final String PROFILE_NAME_HOLDER = "PROFILE_NAME_HOLDER";
    static final String BASE_PROFILE_NAME_HOLDER = "BASE_NAME_HOLDER";
    static final String APP_PROFILE = String.join(NL,
                                                  "RestrictedSecurity.OpenJCEPlusFIPS." + PROFILE_NAME_HOLDER
                                                      + ".desc.name = OpenJCEPlusFIPS Cryptographic Module FIPS 140-3 for Liberty Application",
                                                  "RestrictedSecurity.OpenJCEPlusFIPS." + PROFILE_NAME_HOLDER + ".extends = RestrictedSecurity.OpenJCEPlusFIPS."
                                                                                                                                                + BASE_PROFILE_NAME_HOLDER,
                                                  "");

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

        if (ProductInfo.getBetaEdition()) {
            stdout.println("BETA: The SecurityUtility configureFIPS task is only available in beta." + NL);
        }

        String serverName = getArgumentValue(ARG_SERVER, args, null);
        String clientName = getArgumentValue(ARG_CLIENT, args, null);
        String customProfileFile = getArgumentValue(ARG_CUSTOMPROFILE_FILE, args, null);
        boolean disable = Arrays.asList(args).contains(ARG_DISABLE);

        if (!disable && (!isIbmSdk() && !isSemeru())) {
            stdout.println(getMessage("configureFIPS.notIbmSdkNorSemeru"));
            return SecurityUtilityReturnCodes.ERR_GENERIC;
        }

        if (serverName == null && clientName == null) {
            String etcDir = fileUtility.getServersDirectory() + ".." + SLASH + ".." + SLASH + "etc" + SLASH; // TODO: get install directory in a better way
            String envFileLocation = fileUtility.resolvePath(etcDir + DEFAULT_ENV);

            if (disable) {
                SecurityUtilityReturnCodes rc = handleFileToDisableFips(envFileLocation);
                if (rc != SecurityUtilityReturnCodes.OK) {
                    return rc;
                }
            } else {
                String customProfileFilePaths = "";
                if (isSemeru()) {
                    customProfileFilePaths = customProfileFile;
                    if (customProfileFilePaths == null) {
                        customProfileFilePaths = etcDir + APP_PROFILE_FILE_NAME;
                    }
                }

                SecurityUtilityReturnCodes rc = handleFilesToEnableFips(envFileLocation, customProfileFilePaths);
                if (rc != SecurityUtilityReturnCodes.OK) {
                    return rc;
                }
            }
        }

        if (serverName != null) {
            String usrServers = fileUtility.getServersDirectory();
            String serverDir = usrServers + serverName + SLASH;

            if (!fileUtility.exists(serverDir)) {
                usrServers = fileUtility.resolvePath(usrServers);
                stdout.println(getMessage("configureFIPS.abort"));
                stdout.println(getMessage("serverNotFound", serverName, usrServers));
                return SecurityUtilityReturnCodes.ERR_SERVER_NOT_FOUND;
            }

            String envFileLocation = fileUtility.resolvePath(serverDir + SLASH + SERVER_ENV);

            if (disable) {
                SecurityUtilityReturnCodes rc = handleFileToDisableFips(envFileLocation);
                if (rc != SecurityUtilityReturnCodes.OK) {
                    return rc;
                }
            } else {
                String customProfileFilePaths = "";
                if (isSemeru()) {
                    customProfileFilePaths = customProfileFile;
                    if (customProfileFilePaths == null) {
                        customProfileFilePaths = serverDir + "resources" + SLASH + "security" + SLASH + APP_PROFILE_FILE_NAME;
                    }
                }

                SecurityUtilityReturnCodes rc = handleFilesToEnableFips(envFileLocation, customProfileFilePaths);
                if (rc != SecurityUtilityReturnCodes.OK) {
                    return rc;
                }
            }
        }

        if (clientName != null) {
            String usrClients = fileUtility.getClientsDirectory();
            String clientDir = usrClients + clientName + SLASH;

            if (!fileUtility.exists(clientDir)) {
                usrClients = fileUtility.resolvePath(usrClients);
                stdout.println(getMessage("configureFIPS.abort"));
                stdout.println(getMessage("clientNotFound", serverName, usrClients));
                return SecurityUtilityReturnCodes.ERR_CLIENT_NOT_FOUND;
            }

            String envFileLocation = fileUtility.resolvePath(clientDir + SLASH + CLIENT_ENV);

            if (disable) {
                SecurityUtilityReturnCodes rc = handleFileToDisableFips(envFileLocation);
                if (rc != SecurityUtilityReturnCodes.OK) {
                    return rc;
                }
            } else {
                String customProfileFilePaths = "";
                if (isSemeru()) {
                    customProfileFilePaths = customProfileFile;
                    if (customProfileFilePaths == null) {
                        customProfileFilePaths = clientDir + "resources" + SLASH + "security" + SLASH + APP_PROFILE_FILE_NAME;
                    }
                }

                SecurityUtilityReturnCodes rc = handleFilesToEnableFips(envFileLocation, customProfileFilePaths);
                if (rc != SecurityUtilityReturnCodes.OK) {
                    return rc;
                }
            }
        }

        return SecurityUtilityReturnCodes.OK;
    }

    private boolean isSemeru() {
        return true;
//        String javaHome = getJavaHome();
//        if (javaHome.endsWith(SLASH)) {
//            return fileUtility.exists(javaHome + "lib" + SLASH + "C" + SLASH + "icc" + SLASH + "icclib" + SLASH);
//        }
//        return fileUtility.exists(javaHome + SLASH + "lib" + SLASH + "C" + SLASH + "icc" + SLASH + "icclib" + SLASH);
    }

    private boolean isIbmSdk() {
        String javaHome = getJavaHome();
        if (javaHome.endsWith("jre" + SLASH)) {
            return fileUtility.exists(javaHome + "fips140-3" + SLASH);
        }
        if (javaHome.endsWith("jre")) {
            return fileUtility.exists(javaHome + SLASH + "fips140-3" + SLASH);
        }
        if (javaHome.endsWith(SLASH)) {
            return fileUtility.exists(javaHome + "jre" + SLASH + "fips140-3" + SLASH);
        }
        return fileUtility.exists(javaHome + SLASH + "jre" + SLASH + "fips140-3" + SLASH);
    }

    private String getJavaHome() {
        String javaHome = System.getenv("JAVA_HOME");
        if (javaHome == null) {
            javaHome = System.getenv("JRE_HOME");
        }
        if (javaHome == null) {
            javaHome = System.getenv("WLP_DEFAULT_JAVA_HOME");
        }
        if (javaHome == null) {
            javaHome = System.getProperty("java.home");
        }
        return javaHome;
    }

    private SecurityUtilityReturnCodes handleFilesToEnableFips(String envFileLocation, String customProfileFilePaths) {
        if (customProfileFilePaths.isEmpty()) {
            stdout.println(getMessage("configureFIPS.configureIbmSdk"));

            customProfileFilePaths = "true";
        } else {
            stdout.println(getMessage("configureFIPS.configureSemeru"));

            String[] customProfileFileLocations = customProfileFilePaths.split(PATH_SEPARATOR);
            File previousCustomProfileFile = null;
            for (int i = 0; i < customProfileFileLocations.length; i++) {
                customProfileFileLocations[i] = fileUtility.resolvePath(customProfileFileLocations[i]);
                String customProfileFileLocation = customProfileFileLocations[i];

                File customProfileFile = new File(customProfileFileLocation);
                if (!fileUtility.createParentDirectory(stdout, customProfileFile)) {
                    stdout.println(getMessage("configureFIPS.abortSemeruFile"));
                    stdout.println(getMessage("file.requiredDirNotCreated", customProfileFileLocation));
                    return SecurityUtilityReturnCodes.ERR_PATH_CANNOT_BE_CREATED;
                }

                if (fileUtility.exists(customProfileFile)) {
                    stdout.println(getMessage("configureFIPS.fileExists", customProfileFileLocation));
                    continue;
                }

                // TODO sanitize names
                String profileName = FilenameUtils.removeExtension(customProfileFile.getName());
                String baseProfileName = FilenameUtils.removeExtension(previousCustomProfileFile == null ? LIBERTY_PROFILE_FILE_NAME : previousCustomProfileFile.getName());
                String customProfile = APP_PROFILE.replaceAll(PROFILE_NAME_HOLDER, profileName).replaceAll(BASE_PROFILE_NAME_HOLDER, baseProfileName);
                fileUtility.writeToFile(stderr, customProfile, customProfileFile);
                stdout.println(getMessage("configureFIPS.createdSemeruFile", customProfileFileLocation));

                previousCustomProfileFile = customProfileFile;
            }
            customProfileFilePaths = String.join(PATH_SEPARATOR, customProfileFileLocations);
        }

        File envFile = new File(envFileLocation);

        if (!fileUtility.createParentDirectory(stdout, envFile)) {
            stdout.println(getMessage("configureFIPS.abortEnvFile"));
            stdout.println(getMessage("file.requiredDirNotCreated", envFileLocation));
            return SecurityUtilityReturnCodes.ERR_PATH_CANNOT_BE_CREATED;
        }

        return setFipsEnvironmentVariable(envFile, customProfileFilePaths);
    }

    private SecurityUtilityReturnCodes handleFileToDisableFips(String envFileLocation) {
        File envFile = new File(envFileLocation);
        return disableFipsEnvironmentVariable(envFile);
    }

    /**
     * Set the ENABLE_FIPS140_3 environment variable in the specified .env file.
     * For the case of IBM SDK, it should be empty string.
     * For the case of IBM Semeru Runtimes, it should be the path to the user's custom profile file.
     *
     * @param file
     * @param value
     */
    private SecurityUtilityReturnCodes setFipsEnvironmentVariable(File file, String value) {
        if (!fileUtility.exists(file)) {
            fileUtility.writeToFile(stderr, ENABLE_FIPS140_3_ENV_VAR + "=" + value + NL, file);
            stdout.println(getMessage("configureFIPS.createdEnvFileToEnableFips", fileUtility.resolvePath(file)));
            stdout.println(getMessage("configureFIPS.restartServer"));
            return SecurityUtilityReturnCodes.OK;
        }

        try (RandomAccessFile randomAccessFile = new RandomAccessFile(fileUtility.resolvePath(file), "rw")) {
            boolean enabled = false;

            String line = "";
            long currentPosition = randomAccessFile.getFilePointer();
            while ((line = randomAccessFile.readLine()) != null) {
                if (line.startsWith(ENABLE_FIPS140_3_ENV_VAR + "=")) {
                    if (line.equals(ENABLE_FIPS140_3_ENV_VAR + "=false")) {
                        long nextPosition = randomAccessFile.getFilePointer(); // idx of start of next line

                        String updatedLine = ENABLE_FIPS140_3_ENV_VAR + "=" + value;
                        updateLine(randomAccessFile, line, updatedLine, currentPosition, nextPosition);

                        enabled = true;
                    } else {
                        stdout.println(getMessage("configureFIPS.abortEnvFile"));
                        stdout.println(getMessage("configureFIPS.fipsAlreadyEnabled", fileUtility.resolvePath(file)));
                        return SecurityUtilityReturnCodes.ERR_GENERIC;
                    }
                }

                currentPosition = randomAccessFile.getFilePointer();
            }

            if (!enabled) {
                boolean endsOnANewLine = randomAccessFile.read() == '\n';
                String beginning = endsOnANewLine ? "" : NL;
                String end = endsOnANewLine ? NL : "";

                String enableFipsLine = beginning + ENABLE_FIPS140_3_ENV_VAR + "=" + value + end;
                randomAccessFile.write(enableFipsLine.getBytes(StandardCharsets.UTF_8));
            }
        } catch (IOException e) {
            stdout.println(getMessage("configureFIPS.abortEnvFile"));
            e.printStackTrace(stdout);
            return SecurityUtilityReturnCodes.ERR_GENERIC;
        }

        stdout.println(getMessage("configureFIPS.updatedEnvFileToEnableFips", fileUtility.resolvePath(file)));
        stdout.println(getMessage("configureFIPS.restartServer"));
        return SecurityUtilityReturnCodes.OK;
    }

    /**
     * Comments out the ENABLE_FIPS140_3 environment variable in the specified .env file.
     *
     * @param file
     */
    private SecurityUtilityReturnCodes disableFipsEnvironmentVariable(File file) {
        if (!fileUtility.exists(file)) {
            stdout.println(getMessage("configureFIPS.abortEnvFile"));
            stdout.println(getMessage("configureFIPS.fileDoesNotExist", fileUtility.resolvePath(file)));
            return SecurityUtilityReturnCodes.ERR_GENERIC;
        }

        boolean disabled = false;
        try (RandomAccessFile randomAccessFile = new RandomAccessFile(fileUtility.resolvePath(file), "rw")) {
            String line = "";
            long currentPosition = randomAccessFile.getFilePointer();
            while ((line = randomAccessFile.readLine()) != null) {
                if (line.startsWith(ENABLE_FIPS140_3_ENV_VAR + "=") && !line.equals(ENABLE_FIPS140_3_ENV_VAR + "=false")) {
                    long nextPosition = randomAccessFile.getFilePointer(); // idx of start of next line

                    String updatedLine = ENABLE_FIPS140_3_ENV_VAR + "=false";
                    updateLine(randomAccessFile, line, updatedLine, currentPosition, nextPosition);

                    disabled = true;
                }
                currentPosition = randomAccessFile.getFilePointer();
            }
        } catch (IOException e) {
            stdout.println(getMessage("configureFIPS.abortEnvFile"));
            e.printStackTrace(stdout);
            return SecurityUtilityReturnCodes.ERR_GENERIC;
        }

        if (!disabled) {
            stdout.println(getMessage("configureFIPS.abortEnvFile"));
            stdout.println(getMessage("configureFIPS.fipsNotEnabled", fileUtility.resolvePath(file)));
            return SecurityUtilityReturnCodes.ERR_GENERIC;
        }

        stdout.println(getMessage("configureFIPS.updatedEnvFileToDisableFips", fileUtility.resolvePath(file)));
        stdout.println(getMessage("configureFIPS.restartServer"));
        return SecurityUtilityReturnCodes.OK;
    }

    private void updateLine(RandomAccessFile randomAccessFile, String currentLine, String updatedLine, long currentPosition, long nextPosition) throws IOException {
        byte[] restOfTheFileFromNextLine = new byte[(int) (randomAccessFile.length() - nextPosition)];
        randomAccessFile.readFully(restOfTheFileFromNextLine);

        byte[] lineSeparator = new byte[(int) (nextPosition - (currentPosition + currentLine.length()))];

        randomAccessFile.setLength(currentPosition); // truncate file to start of current line
        randomAccessFile.seek(currentPosition);
        randomAccessFile.write(updatedLine.getBytes(StandardCharsets.UTF_8));
        randomAccessFile.write(lineSeparator);
        randomAccessFile.write(restOfTheFileFromNextLine);
        randomAccessFile.seek(currentPosition + updatedLine.length() + lineSeparator.length);
    }

    /** {@inheritDoc} */
    @Override
    boolean isKnownArgument(String arg) {
        return arg.equals(ARG_SERVER)
               || arg.equals(ARG_CLIENT)
               || arg.equals(ARG_DISABLE)
               || arg.equals(ARG_CUSTOMPROFILE_FILE);
    }

    /** {@inheritDoc} */
    @Override
    void checkRequiredArguments(String[] args) throws IllegalArgumentException {
        String message = "";
        // We expect at least the task name
        if (args.length < 1) {
            message = getMessage("insufficientArgs");
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
