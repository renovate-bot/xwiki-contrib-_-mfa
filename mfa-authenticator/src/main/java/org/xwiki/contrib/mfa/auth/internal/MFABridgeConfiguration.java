/*
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.xwiki.contrib.mfa.auth.internal;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.container.Container;
import org.xwiki.container.Session;
import org.xwiki.container.servlet.ServletSession;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.security.authservice.XWikiAuthServiceComponent;

import com.xpn.xwiki.user.api.XWikiAuthService;

/**
 * Various MFA bridged authenticator configurations.
 * 
 * @version $Id$
 */
@Component(roles = MFABridgeConfiguration.class)
@Singleton
public class MFABridgeConfiguration extends MFAConfiguration
{
    /**
     * The prefix used for MFA bridge configuration properties.
     */
    public static final String PREFIX_PROP = MFAConfiguration.PREFIX_PROP + "bridge.";

    /**
     * The name of the property containing the authenticator to fallback to.
     */
    public static final String PROP_AUTHENTICATOR = PREFIX_PROP + "authenticator";

    private static final String SESSION = "mfa";

    private static final String SESSION_VALID = "valid";

    private static final String SESSION_XWIKIUSER = "xwikiuser";

    @Inject
    private Container container;

    @Inject
    @Named("standard")
    private XWikiAuthServiceComponent standardAuthenticator;

    @Inject
    private Logger logger;

    /**
     * @param create true if it should be created when it does not exist
     * @return the MFA specific session metadata
     */
    public Map<String, Object> getMFASession(boolean create)
    {
        Session session = this.container.getSession();
        if (session instanceof ServletSession) {
            HttpSession httpSession = ((ServletSession) session).getHttpSession();

            this.logger.debug("Session: {}", httpSession.getId());

            Map<String, Object> oidcSession = (Map<String, Object>) httpSession.getAttribute(SESSION);
            if (oidcSession == null && create) {
                oidcSession = new ConcurrentHashMap<>();
                httpSession.setAttribute(SESSION, oidcSession);
            }

            return oidcSession;
        }

        return null;
    }

    /**
     * @param <T> the type of the attribute
     * @param name the name of the attribute
     * @param def the default value of the attribute
     * @return the attribute value, or the default value if none could be found
     */
    public <T> T getSessionAttribute(String name, T def)
    {
        Map<String, Object> session = getMFASession(false);
        if (session != null) {
            return (T) session.getOrDefault(name, def);
        }

        return def;
    }

    /**
     * @param <T> the type of the attribute
     * @param name the name of the attribute
     * @return the previous value of the attribute
     */
    public <T> T removeSessionAttribute(String name)
    {
        Map<String, Object> session = getMFASession(false);
        if (session != null) {
            try {
                return (T) session.get(name);
            } finally {
                session.remove(name);
            }
        }

        return null;
    }

    /**
     * @param name the name of the attribute
     * @param value the value to set
     */
    public void setSessionAttribute(String name, Object value)
    {
        Map<String, Object> session = getMFASession(true);
        if (session != null) {
            session.put(name, value);
        }
    }

    /**
     * @return true if the current session is validated
     */
    public boolean isValid()
    {
        return getSessionAttribute(SESSION_VALID, false);
    }

    /**
     * @param valid true if the current session is validated
     */
    public void setValid(boolean valid)
    {
        setSessionAttribute(SESSION_VALID, valid);
    }

    /**
     * @return the user being validated
     */
    public DocumentReference getUserReference()
    {
        return getSessionAttribute(SESSION_XWIKIUSER, null);
    }

    /**
     * @param user the user being validated
     */
    public void setUserReference(DocumentReference user)
    {
        setSessionAttribute(SESSION_XWIKIUSER, user);
    }

    /**
     * Remove the user being validated.
     */
    public void removeUserReference()
    {
        removeSessionAttribute(SESSION_XWIKIUSER);
    }

    /**
     * @return the authenticator to fallback to
     */
    public XWikiAuthService getAuthenticator()
    {
        String authenticatorString = getProperty(PROP_AUTHENTICATOR, null);

        if (authenticatorString != null) {
            // Try as hint
            // TODO

            // Try as class
            // TODO
        }

        // Fallback on the standard authenticator
        return this.standardAuthenticator;
    }
}
