/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 1997-2010 Oracle and/or its affiliates. All rights reserved.
 *
 * The contents of this file are subject to the terms of either the GNU
 * General Public License Version 2 only ("GPL") or the Common Development
 * and Distribution License("CDDL") (collectively, the "License").  You
 * may not use this file except in compliance with the License.  You can
 * obtain a copy of the License at
 * https://glassfish.dev.java.net/public/CDDL+GPL_1_1.html
 * or packager/legal/LICENSE.txt.  See the License for the specific
 * language governing permissions and limitations under the License.
 *
 * When distributing the software, include this License Header Notice in each
 * file and include the License file at packager/legal/LICENSE.txt.
 *
 * GPL Classpath Exception:
 * Oracle designates this particular file as subject to the "Classpath"
 * exception as provided by Oracle in the GPL Version 2 section of the License
 * file that accompanied this code.
 *
 * Modifications:
 * If applicable, add the following below the License Header, with the fields
 * enclosed by brackets [] replaced by your own identifying information:
 * "Portions Copyright [year] [name of copyright owner]"
 *
 * Contributor(s):
 * If you wish your version of this file to be governed by only the CDDL or
 * only the GPL Version 2, indicate your decision by adding "[Contributor]
 * elects to include this software in this distribution under the [CDDL or GPL
 * Version 2] license."  If you don't indicate a single choice of license, a
 * recipient has the option to distribute your version of this file under
 * either the CDDL, the GPL Version 2 or to extend the choice of license to
 * its licensees as provided above.  However, if you add GPL Version 2 code
 * and therefore, elected the GPL Version 2 license, then the option applies
 * only if the new code is made subject to such option by the copyright
 * holder.
 */
package net.eisele.glassfish.security.securejdbcrealm;

import com.sun.appserv.security.AppservPasswordLoginModule;
import com.sun.enterprise.security.auth.login.PasswordLoginModule;
import javax.security.auth.login.LoginException;
import java.util.Arrays;
import java.util.logging.Level;

/**
 * Login-Module for the SecureJDBCRealm login module
 * @author Markus Eisele www.eisele.net
 */
public class SecureJDBCLoginModule extends AppservPasswordLoginModule {

    /**
     * Perform JDBC authentication. Delegates to JDBCRealm.
     *
     * @throws LoginException If login fails (JAAS login() behavior).
     */
    @Override
    protected void authenticateUser() throws LoginException {
        if (!(_currentRealm instanceof SecureJDBCRealm)) {
            String msg = sm.getString("jdbclm.badrealm");
            throw new LoginException(msg);
        }

        final SecureJDBCRealm jdbcRealm = (SecureJDBCRealm) _currentRealm;

        // A JDBC user must have a name not null and non-empty.
        if ((_username == null) || (_username.length() == 0)) {
            String msg = sm.getString("jdbclm.nulluser");
            throw new LoginException(msg);
        }

        String[] grpList = jdbcRealm.authenticate(_username, getPasswordChar());

        if (_logger.isLoggable(Level.FINEST)) {
            _logger.log(Level.FINEST, "JDBC login: Tries left {0}", jdbcRealm.getTriesLeft());
        }

        if (grpList == null) {  // JAAS behavior
            String msg = sm.getString("jdbclm.loginfail", _username);
            msg += "Tries left " + jdbcRealm.getTriesLeft();
            throw new LoginException(msg);
        }

        if (_logger.isLoggable(Level.FINEST)) {
            _logger.log(Level.FINEST, "JDBC login succeeded for: {0} groups:{1}", new Object[]{_username, Arrays.toString(grpList)});
        }

        commitUserAuthentication(grpList);
    }
}